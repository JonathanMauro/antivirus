# THUGAS KILL VIRUS

Antivírus para Windows com arquitetura modular: núcleo em Rust, interface em Tauri e camada de IA em Python.
Os requisitos completos estão em [Projeto_Antivirus_Requisitos_e_Arquitetura.txt](Projeto_Antivirus_Requisitos_e_Arquitetura.txt).

## Estrutura

```
crates/tkv-core/   Núcleo: SHA-256, entropia, assinaturas, heurísticas, scanner
crates/tkv-cli/    CLI "tkv" para testar o motor
app/               Aplicativo desktop Tauri (ver app/README.md)
ml/                IA: extração de atributos (pefile) e Isolation Forest
rules/yara/        Regras YARA (Fase 2)
signatures/        Base de assinaturas por hash
```

## Ambiente

1. **Rust:** instale pelo <https://rustup.rs>. Ele vai pedir o *Visual Studio Build Tools* com a carga "Desenvolvimento para desktop com C++".
2. **Node.js LTS:** necessário para a interface Tauri.
3. **Python 3.10+:** já instalado.

## Comandos

```powershell
# Núcleo
cargo test
cargo run -p tkv-cli -- scan C:\caminho\para\pasta
cargo run -p tkv-cli -- scan . --signatures signatures\hashes.txt --json
cargo run -p tkv-cli -- hash arquivo.exe

# Histórico e quarentena
cargo run -p tkv-cli -- scan C:\pasta --quarantine   # isola só os MALICIOSOS
cargo run -p tkv-cli -- history                      # últimas varreduras
cargo run -p tkv-cli -- history 3                    # detecções da varredura #3
cargo run -p tkv-cli -- quarantine list [--all]
cargo run -p tkv-cli -- quarantine add arquivo.exe
cargo run -p tkv-cli -- quarantine restore <id> [--overwrite]
cargo run -p tkv-cli -- quarantine delete <id>

# IA
cd ml
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest
python -m tkv_ml.features C:\Windows\System32 data\limpos.csv
python -m tkv_ml.anomaly train data\limpos.csv models\iforest.joblib
```

## Dados locais

Os dados ficam em `%LOCALAPPDATA%\ThugasKillVirus`, ou no diretório indicado em `--data-dir`:

- `tkv.db`: banco SQLite com as varreduras, as detecções, a quarentena e as configurações.
- `quarantine\<id>.qtn`: arquivos isolados. O conteúdo é cifrado com XOR, o que impede que sejam executados ou detectados de novo. Na restauração, o SHA-256 é conferido.

Ao usar `--quarantine`, só os arquivos **maliciosos** (assinatura confirmada) são isolados automaticamente. Os **suspeitos** (detectados só por heurística) aparecem no relatório e podem ser isolados manualmente com `quarantine add`.

## Como funciona o Risk Score (versão inicial)

| Sinal | Pontos |
|---|---|
| Hash na base de assinaturas | 100 (malicioso) |
| Extensão dupla enganosa (`fatura.pdf.exe`) | 45 |
| Executável PE com extensão de não executável | 35 |
| PE com entropia > 7.2 (possível packer) | 25 |
| PE sem extensão | 10 |

Uma pontuação de 40 ou mais classifica o arquivo como **suspeito**. Os pesos são provisórios e precisam ser calibrados com dados reais.

## Segurança no desenvolvimento

- Teste malware real **somente** em uma máquina virtual isolada.
- Para validar a detecção, use o arquivo **EICAR**. Os testes automatizados o montam em memória e nunca o gravam em disco.
- Nunca versione amostras. As pastas `samples/` e `quarantine/` estão no `.gitignore`.
