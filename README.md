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
cargo run -p tkv-cli -- inspect arquivo.exe          # PE, YARA, heurísticas e veredito
cargo run -p tkv-cli -- scan C:\pasta --rules rules\yara

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

## Motor de detecção

O veredito segue esta ordem de prioridade:

1. **Assinatura por hash (SHA-256):** **malicioso**, com risco 100.
2. **Regra YARA marcada como `malicious = true`:** **malicioso**, com risco 100.
3. **Soma das pontuações** das heurísticas e das demais regras YARA: 40 pontos ou mais classificam o arquivo como **suspeito**.

Cada detecção recebe uma **categoria**: teste, cavalo de Troia, ransomware, worm, backdoor, spyware, adware, programa indesejado, ferramenta de ataque, exploit, downloader ou genérico.

### Heurísticas (Risk Score)

| Sinal | Pontos |
|---|---|
| Extensão dupla enganosa (`fatura.pdf.exe`) | 45 |
| Executável PE com extensão de não executável | 35 |
| Importa funções de injeção de código em outros processos (só .exe) | 35 |
| Importa funções de *process hollowing* (só .exe) | 30 |
| Seção de empacotador conhecido (UPX, VMProtect, Themida…) | 25 |
| Ponto de entrada fora das seções ou em seção de dados | 25 |
| Arquivo não PE com entropia acima de 7.2 | 25 |
| Seção de código com entropia acima de 7.2 (código cifrado) | 20 |
| Importa funções de captura de teclado (só .exe) | 20 |
| Seção gravável e executável | 15 |
| Executável sem funções importadas / com até 3 | 15 / 10 |
| PE sem extensão | 10 |

Arquivos de até 64 MB passam por análise profunda (estrutura PE e YARA). Arquivos maiores recebem só a verificação de hash e de cabeçalho.

### Falsos positivos medidos

Varredura completa de `C:\Windows\System32`: 17.386 arquivos (4,5 GB). Dois falsos positivos encontrados e corrigidos:

- `kernel32.dll`: as combinações de funções agora valem só para executáveis, não para DLLs.
- `Microsoft.PowerShell.Utility.psd1`: a regra YARA agora exige a estrutura real de download e execução, e não só os nomes dos comandos.

Os testes automatizados cobrem os dois casos.

As assinaturas aceitam um terceiro campo opcional com a categoria: `<sha256>;<nome>;<categoria>`.

## Segurança no desenvolvimento

- Teste malware real **somente** em uma máquina virtual isolada.
- Para validar a detecção, use o arquivo **EICAR**. Os testes automatizados o montam em memória e nunca o gravam em disco.
- Nunca versione amostras. As pastas `samples/` e `quarantine/` estão no `.gitignore`.
