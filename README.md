# 🔒 Secure NPM — Script 

Este repositório contém um **script único em Node.js** que detecta se seu projeto possui **dependências comprometidas** em ataques de *supply chain* no **npm** (também funciona com **Yarn** e **Pnpm**) e oferece um fluxo interativo para **remover** ou **voltar para versões seguras** automaticamente.

O foco inicial é o incidente de **08–09/09/2025**, quando diversos pacotes populares (`chalk`, `debug`, `ansi-*`, `color-*`, `duckdb`, `prebid`, etc.) foram publicados com versões maliciosas.

---

## 📦 O que o script faz
1. **Escaneia lockfiles** (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`);
2. **Identifica versões maliciosas** conhecidas;
3. Para cada ocorrência encontrada:
   - Se for **dependência direta**:  
     ➝ Pergunta se você quer **Remover** ou **Voltar para uma versão segura**;
   - Se for **dependência transitiva**:  
     ➝ Pergunta se você quer adicionar **override/resolution** no `package.json`;
4. Faz a reinstalação com **lockfile congelado** para manter reprodutibilidade.

---

## 🚀 Como usar

### 1. Clone ou copie o script
Crie a pasta `scripts/` no seu projeto e adicione o arquivo:


> O conteúdo completo do script está neste repositório.

---

### 2. Torne executável (opcional, Linux/Mac)
```bash
chmod +x scripts/secure-npm.mjs
```

### 3. Execute
node scripts/secure-npm.mjs

O script vai:

Ler seu package-lock.json, yarn.lock ou pnpm-lock.yaml;

Listar pacotes comprometidos (se existirem);

Perguntar a ação desejada:

>>> chalk@5.6.1 (dependência direta)
Ação [R=Remover | V=Voltar p/ versão segura | S=Pular]:




