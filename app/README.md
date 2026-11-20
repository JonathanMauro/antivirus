# Interface gráfica (Tauri)

A interface ficará aqui. Ela usa HTML/CSS/JS no frontend e Rust no backend, que importa o crate `tkv-core`.

Pré-requisitos: Rust, Node.js LTS e o WebView2, que já vem no Windows 11.

```powershell
cd app
npm create tauri-app@latest .
```

Em seguida, adicione `tkv-core = { path = "../crates/tkv-core" }` às dependências do `src-tauri/Cargo.toml` e inclua `app/src-tauri` em `members` no `Cargo.toml` da raiz.

Arquitetura alvo, conforme a seção 5 do documento de requisitos: na Fase 3, a interface passa a falar por IPC com um **serviço Windows** separado, que executa as operações privilegiadas (quarentena e proteção em tempo real). A própria interface nunca executa essas operações.
