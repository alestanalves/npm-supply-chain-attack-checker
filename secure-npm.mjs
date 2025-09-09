#!/usr/bin/env node
/**
 * secure-npm.mjs — verificador interativo de supply chain (npm/yarn/pnpm)
 * - Escaneia lockfiles por versões comprometidas (lista embutida)
 * - Exibe relatório
 * - Para cada ocorrência:
 *    • se for dependência direta: perguntar "Remover" ou "Voltar (downgrade/upgrade) p/ versão segura"
 *    • se for dependência transitiva: oferecer "Adicionar override/resolution"
 * - Aplica mudanças no package.json e executa o gerenciador de pacotes apropriado
 *
 * Requisitos: Node 18+ (ou 16+ com --experimental-modules), acesso ao `npm view` para descobrir versões seguras.
 */

import fs from "fs";
import path from "path";
import { execSync, spawnSync } from "child_process";
import readline from "readline";
import process from "process";

const ROOT = process.cwd();
const PKG_JSON = path.join(ROOT, "package.json");
const LOCKFILES = [
  { file: "package-lock.json", type: "npm" },
  { file: "yarn.lock", type: "yarn" },
  { file: "pnpm-lock.yaml", type: "pnpm" },
];

// Lista de versões comprometidas do incidente 08–09/09/2025
const COMPROMISED = [
  { name: "chalk", versions: ["5.6.1"] },
  { name: "chalk-template", versions: ["1.1.1"] },
  { name: "debug", versions: ["4.4.2"] },
  { name: "ansi-regex", versions: ["6.2.1"] },
  { name: "ansi-styles", versions: ["6.2.2"] },
  { name: "has-ansi", versions: ["6.0.1"] },
  { name: "color", versions: ["5.0.1"] },
  { name: "color-convert", versions: ["3.1.1"] },
  { name: "color-name", versions: ["2.0.1"] },
  { name: "color-string", versions: ["2.1.1"] },
  { name: "duckdb", versions: ["1.3.3"] },
  { name: "@duckdb/duckdb-wasm", versions: ["1.29.2"] },
  { name: "@duckdb/node-api", versions: ["1.3.3"] },
  { name: "@duckdb/node-bindings", versions: ["1.3.3"] },
  { name: "error-ex", versions: ["1.3.3"] },
  { name: "is-arrayish", versions: ["0.3.3"] },
  { name: "backslash", versions: ["0.2.1"] },
  { name: "prebid", versions: ["10.9.2"] },
  { name: "prebid.js", versions: ["10.9.2"] },
  { name: "prebid-universal-creative", versions: ["1.17.3"] },
];

// --------- utilidades básicas ---------
function fileOrNull(p) {
  const abs = path.join(ROOT, p);
  return fs.existsSync(abs) ? abs : null;
}

function readTextOrNull(p) {
  try {
    return fs.readFileSync(p, "utf8");
  } catch {
    return null;
  }
}

function readJsonOrNull(p) {
  try {
    return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch {
    return null;
  }
}

function semverCompare(a, b) {
  // comparação simples sem pré-releases: "x.y.z"
  const pa = String(a).split(".").map(n => parseInt(n, 10));
  const pb = String(b).split(".").map(n => parseInt(n, 10));
  for (let i = 0; i < 3; i++) {
    const da = pa[i] || 0, db = pb[i] || 0;
    if (da > db) return 1;
    if (da < db) return -1;
  }
  return 0;
}

function unique(arr) { return Array.from(new Set(arr)); }

function detectPM() {
  // heurística: lockfile presente > npm_config_user_agent
  const hasNpm = fileOrNull("package-lock.json");
  const hasYarn = fileOrNull("yarn.lock");
  const hasPnpm = fileOrNull("pnpm-lock.yaml");

  if (hasPnpm) return "pnpm";
  if (hasYarn) return "yarn";
  if (hasNpm) return "npm";

  // fallback por user agent
  const ua = process.env.npm_config_user_agent || "";
  if (ua.includes("pnpm")) return "pnpm";
  if (ua.includes("yarn")) return "yarn";
  return "npm";
}

function run(cmd, opts = {}) {
  return execSync(cmd, { stdio: "pipe", encoding: "utf8", ...opts }).trim();
}

function safeJson(obj) {
  return JSON.stringify(obj, null, 2) + "\n";
}

// --------- leitura de dependências ---------
function readDirectDeps() {
  const pkg = readJsonOrNull(PKG_JSON) || {};
  const deps = {
    ...(pkg.dependencies || {}),
    ...(pkg.devDependencies || {}),
    ...(pkg.peerDependencies || {}),
    ...(pkg.optionalDependencies || {}),
  };
  return deps; // { name: range }
}

function scanLockfiles() {
  const results = [];
  for (const lf of LOCKFILES) {
    const p = fileOrNull(lf.file);
    if (!p) continue;
    const txt = readTextOrNull(p);
    if (!txt) continue;

    for (const c of COMPROMISED) {
      for (const v of c.versions) {
        const nameEsc = c.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const verEsc = v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        let hit = false;

        if (lf.type === "npm") {
          // procurar bloco com "name": "<pkg>" ... "version": "<v>"
          const re = new RegExp(`"name"\\s*:\\s*"${nameEsc}"[\\s\\S]*?"version"\\s*:\\s*"${verEsc}"`, "m");
          hit = re.test(txt);
        } else {
          // yarn/pnpm: procurar "pkg@" e alguma linha version: v
          const re1 = new RegExp(`(^|\\n)${nameEsc}@[^\\s:]*(:|\\n)`, "m");
          const re2 = new RegExp(`version\\s*[:"]\\s*"?${verEsc}"?`, "m");
          hit = re1.test(txt) && re2.test(txt);
        }

        if (hit) {
          results.push({ name: c.name, version: v, lockfile: lf.file, pm: lf.type });
        }
      }
    }
  }
  return results;
}

function isDirectDependency(pkgName) {
  const deps = readDirectDeps();
  return Object.prototype.hasOwnProperty.call(deps, pkgName);
}

// --------- consulta de versões seguras ---------
function fetchAllVersionsFromRegistry(pkgName) {
  try {
    // `npm view <pkg> versions --json`
    const out = run(`npm view "${pkgName}" versions --json`, { stdio: "pipe" });
    const parsed = JSON.parse(out);
    if (Array.isArray(parsed)) return parsed;
  } catch (e) {
    // pode falhar em escopos privados; retornar vazio
  }
  return [];
}

function pickSafeVersion(pkgName, badVersion) {
  const all = fetchAllVersionsFromRegistry(pkgName);
  if (all.length === 0) return null;

  // estratégia: pegar a MAIOR versão diferente da comprometida
  const filtered = all.filter(v => v !== badVersion).sort(semverCompare);
  const best = filtered[filtered.length - 1] || null;

  // fallback: se não houver maior, tentar imediatamente anterior
  if (!best) {
    // teoricamente não cai aqui; se cair, retorna primeira diferente
    return all.find(v => v !== badVersion) || null;
  }
  return best;
}

// --------- prompts ---------
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (q) => new Promise(res => rl.question(q, ans => res(ans.trim())));

// --------- ações ---------
function writePackageJson(modifier) {
  const pkg = readJsonOrNull(PKG_JSON) || {};
  const changed = modifier(pkg) || pkg;
  fs.writeFileSync(PKG_JSON, safeJson(changed));
}

function addOverrides(pkgName, targetVersion) {
  writePackageJson(pkg => {
    // npm overrides
    pkg.overrides = pkg.overrides || {};
    pkg.overrides[pkgName] = targetVersion;

    // yarn resolutions
    pkg.resolutions = pkg.resolutions || {};
    pkg.resolutions[pkgName] = targetVersion;

    // pnpm overrides (dentro do bloco pnpm)
    pkg.pnpm = pkg.pnpm || {};
    pkg.pnpm.overrides = pkg.pnpm.overrides || {};
    pkg.pnpm.overrides[pkgName] = targetVersion;

    return pkg;
  });
  console.log(`   → overrides/resolutions adicionados: ${pkgName}@${targetVersion}`);
}

function removeDirectDependency(pm, pkgName) {
  if (pm === "yarn") {
    spawnSync("yarn", ["remove", pkgName], { stdio: "inherit" });
  } else if (pm === "pnpm") {
    spawnSync("pnpm", ["remove", pkgName], { stdio: "inherit" });
  } else {
    spawnSync("npm", ["uninstall", pkgName], { stdio: "inherit" });
  }
}

function installDirectDependency(pm, pkgName, version, saveDev = false) {
  const spec = `${pkgName}@${version}`;
  if (pm === "yarn") {
    spawnSync("yarn", ["add", saveDev ? "-D" : "", spec].filter(Boolean), { stdio: "inherit" });
  } else if (pm === "pnpm") {
    spawnSync("pnpm", ["add", saveDev ? "-D" : "", spec].filter(Boolean), { stdio: "inherit" });
  } else {
    spawnSync("npm", ["install", saveDev ? "-D" : "", spec].filter(Boolean), { stdio: "inherit" });
  }
}

function reinstallFrozen(pm) {
  console.log("\n[reinstall] Limpando e reinstalando de forma determinística…");
  try { fs.rmSync(path.join(ROOT, "node_modules"), { recursive: true, force: true }); } catch {}
  try { run("npm cache clean --force"); } catch {}
  if (pm === "yarn") {
    spawnSync("yarn", ["install", "--frozen-lockfile"], { stdio: "inherit" });
  } else if (pm === "pnpm") {
    spawnSync("pnpm", ["install", "--frozen-lockfile"], { stdio: "inherit" });
  } else {
    spawnSync("npm", ["ci"], { stdio: "inherit" });
  }
}

// --------- fluxo principal ---------
(async function main() {
  console.log("[secure-npm] Verificando lockfiles…");
  const hits = scanLockfiles();

  if (hits.length === 0) {
    console.log("[secure-npm] ✅ Nenhuma versão comprometida detectada.");
    rl.close();
    process.exit(0);
  }

  // Consolidar por pacote@versão
  const uniqueHits = unique(hits.map(h => `${h.name}@${h.version}`))
    .map(key => {
      const [name, version] = key.split("@");
      const lf = hits.find(h => h.name === name && h.version === version)?.lockfile || "desconhecido";
      const pm = detectPM();
      return { name, version, lockfile: lf, pm, direct: isDirectDependency(name) };
    });

  console.log("\n🚨 Detectei dependências comprometidas:");
  for (const h of uniqueHits) {
    console.log(`  - ${h.name}@${h.version}  (em: ${h.lockfile})  ${h.direct ? "[direta]" : "[transitiva]"}`);
  }

  console.log("\n[secure-npm] Para cada item, escolha uma ação.");
  for (const h of uniqueHits) {
    console.log(`\n>>> ${h.name}@${h.version}  ${h.direct ? "(dependência direta)" : "(dependência transitiva)"}`);

    if (h.direct) {
      // Dependência direta: remover ou voltar para versão segura
      const choice = (await ask("Ação [R=Remover | V=Voltar p/ versão segura | S=Pular]: ")).toUpperCase();
      if (choice === "R") {
        removeDirectDependency(h.pm, h.name);
        reinstallFrozen(h.pm);
      } else if (choice === "V") {
        const safe = pickSafeVersion(h.name, h.version);
        if (!safe) {
          console.log("   ! Não consegui determinar versão segura no registry. Pulei.");
        } else {
          // Descobrir se estava em devDependencies
          const deps = readJsonOrNull(PKG_JSON) || {};
          const inDev = Boolean(deps.devDependencies && deps.devDependencies[h.name]);
          installDirectDependency(h.pm, h.name, safe, inDev);
          reinstallFrozen(h.pm);
        }
      } else {
        console.log("   (Pulando)");
      }
    } else {
      // Transitiva: oferecer overrides/resolutions
      const safe = pickSafeVersion(h.name, h.version);
      if (!safe) {
        console.log("   ! Não consegui determinar versão segura para override. Pulei.");
        continue;
      }
      const choice = (await ask(`Ação [O=Adicionar override/resolution -> ${h.name}@${safe} | S=Pular]: `)).toUpperCase();
      if (choice === "O") {
        addOverrides(h.name, safe);
        reinstallFrozen(h.pm);
      } else {
        console.log("   (Pulando)");
      }
    }
  }

  console.log("\n[secure-npm] ✅ Processo concluído.");
  rl.close();
  process.exit(0);
})().catch(err => {
  console.error("\n[secure-npm] ERRO:", err?.message || err);
  rl.close();
  process.exit(1);
});
