# Regras YARA

O motor YARA-X do THUGAS KILL VIRUS compila estas regras. Cada arquivo `.yar` ou `.yara` vira um *namespace* com o nome do arquivo.

| Arquivo | Conteúdo |
|---|---|
| `test_files.yar` | Arquivos de teste inofensivos (EICAR) |
| `scripts.yar` | PowerShell e scripts suspeitos: download e execução, comandos codificados, tentativa de desativar o Defender, exclusão de cópias de sombra |
| `ransomware.yar` | Notas de resgate |

## Metadados reconhecidos

```yara
meta:
    description = "texto exibido ao usuário"
    category    = "ransomware"      // test, trojan, ransomware, worm, backdoor, spyware,
                                    // adware, pua, hack_tool, exploit, downloader, generic
    threat      = "Nome.Da.Ameaca"  // nome exibido quando a regra é maliciosa
    score       = 60                // 0 a 100 (padrão 50); soma ao Risk Score
    malicious   = true              // veredito MALICIOSO direto (use com cuidado)
```

Só marque `malicious = true` em regras de altíssima confiança. Nas demais, deixe a pontuação somar com as heurísticas: o arquivo vira **suspeito** ao chegar a 40 pontos.

## Onde as regras são carregadas

- **Aplicativo:** os arquivos desta pasta, incluídos no instalador, e mais `%LOCALAPPDATA%\ThugasKillVirus\rules\`, onde ficam as regras do usuário.
- **CLI:** a pasta passada em `--rules <DIR>`. Sem esse parâmetro, a CLI usa `rules\yara` no diretório atual.

## Boas práticas

- Prefira padrões de **comportamento**, como "baixa e executa", a strings de malwares específicos. Arquivos de regras com muitas strings de malware famoso podem ser marcados por outros antivírus.
- Toda regra nova deve ser testada contra arquivos legítimos, como `C:\Windows\System32`, para medir os falsos positivos.
