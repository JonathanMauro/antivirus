# Interface gráfica (Tauri)

Este é o aplicativo desktop do THUGAS KILL VIRUS. O frontend é feito em **HTML, CSS e JavaScript puros**, sem framework e sem bundler, para ficar o mais leve possível. O backend é escrito em Rust e usa o crate `tkv-core` diretamente.

```
app/
  src/                 Frontend (index.html, styles.css, main.js, logo.png)
  src-tauri/
    src/main.rs        Inicialização: banco, quarentena, assinaturas
    src/commands.rs    Comandos chamados pela interface (invoke)
    tauri.conf.json    Janela, CSP e empacotamento (instalador NSIS)
    capabilities/      Permissões da janela
  app-icon.png         Ícone-fonte (gerar os tamanhos: npx tauri icon app-icon.png)
```

## Comandos

```powershell
cd app
npm install          # só na primeira vez
npm run dev          # roda em modo desenvolvimento
npm run build        # gera o instalador em target\release\bundle\nsis\
```

## Telas

- **Painel:** status geral, última verificação, itens em quarentena e assinaturas.
- **Verificar:** verificação rápida, completa ou personalizada, com progresso em tempo real e botão para cancelar.
- **Histórico:** todas as verificações, com os detalhes e os motivos de cada detecção.
- **Quarentena:** restaurar ou excluir arquivos, sempre com confirmação.
- **Configurações:** isolamento automático e tamanho máximo de arquivo.
- **Barra lateral:** uso de CPU e memória do aplicativo e do sistema.

## Segurança

- **CSP restritiva:** só scripts locais, sem scripts embutidos no HTML.
- **Texto de arquivos tratado com segurança:** nomes e caminhos de arquivos são inseridos com `textContent`, nunca com `innerHTML`, o que impede ataques de injeção de código (XSS) a partir de um nome de arquivo malicioso.
- **Situação atual:** nesta fase, as operações rodam no processo do aplicativo, com as permissões do usuário.
- **Fase 3:** essas operações passam para um **serviço Windows** separado, que fala com a interface por IPC, e a interface deixa de executar ações privilegiadas.
