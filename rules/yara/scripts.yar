// Padrões suspeitos em scripts (PowerShell, batch, VBScript, JScript).
// Nenhuma destas regras é "malicious = true": scripts legítimos de
// administração podem usar técnicas parecidas. Elas somam pontos ao Risk Score.

rule PowerShell_Encoded_Hidden
{
    meta:
        description = "PowerShell com comando codificado e janela oculta"
        category = "downloader"
        score = 45

    strings:
        $ps = "powershell" nocase
        $enc1 = /\s-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/=]{40,}/ nocase
        $hid1 = /-w(indowstyle)?\s+h(idden)?\b/ nocase
        $hid2 = "-nop" nocase

    condition:
        filesize < 5MB and $ps and $enc1 and any of ($hid*)
}

rule PowerShell_Download_And_Execute
{
    meta:
        description = "script baixa conteúdo da internet e executa em memória"
        category = "downloader"
        score = 50

    strings:
        // Exige a ESTRUTURA do ataque (o resultado do download vai direto
        // para execução), não apenas os nomes dos comandos: manifestos de
        // módulos do PowerShell listam esses nomes e não são maliciosos.
        $c1 = /(\bIEX|Invoke-Expression)[\s(]{1,8}[^\r\n]{0,120}\.Download(String|Data)\s*\(/ nocase
        $c2 = /\.Download(String|Data)\s*\([^\r\n]{0,200}\)\s*\)?\s*\|\s*(IEX|Invoke-Expression)\b/ nocase
        $c3 = /\b(Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\s[^|\r\n]{1,200}\|\s*(IEX|Invoke-Expression)\b/ nocase

    condition:
        filesize < 5MB and any of them
}

rule Script_Base64_Payload_Execution
{
    meta:
        description = "script decodifica Base64 e executa o resultado"
        category = "downloader"
        score = 35

    strings:
        // Decodificação e execução na mesma expressão.
        $c1 = /(\bIEX|Invoke-Expression)[\s(]{1,8}[^\r\n]{0,160}FromBase64String/ nocase
        $c2 = /FromBase64String[^\r\n]{0,200}\|\s*(IEX|Invoke-Expression)\b/ nocase
        $c3 = /\[(System\.)?Reflection\.Assembly\]::Load\s*\([^\r\n]{0,80}FromBase64String/ nocase

    condition:
        filesize < 5MB and any of them
}

rule Disable_Windows_Defender
{
    meta:
        description = "tenta desativar a proteção do Windows Defender"
        category = "trojan"
        score = 45

    strings:
        $a1 = /Set-MpPreference\s+.{0,40}-Disable(RealtimeMonitoring|BehaviorMonitoring|IOAVProtection)/ nocase
        $a2 = "Add-MpPreference -ExclusionPath" nocase
        $a3 = /DisableAntiSpyware.{0,40}(\/d\s+1|-Value\s+1)/ nocase

    condition:
        filesize < 10MB and any of them
}

rule Shadow_Copy_Deletion
{
    meta:
        description = "apaga cópias de sombra ou desativa a recuperação do Windows (típico de ransomware)"
        category = "ransomware"
        score = 70

    strings:
        $v1 = /vssadmin(\.exe)?\s+delete\s+shadows/ nocase
        $v2 = /wmic(\.exe)?\s+shadowcopy\s+delete/ nocase
        $v3 = /bcdedit(\.exe)?\s+\/set\s+\{default\}\s+recoveryenabled\s+no/ nocase
        $v4 = /wbadmin(\.exe)?\s+delete\s+catalog/ nocase
        $v5 = /Get-WmiObject\s+Win32_ShadowCopy.{0,60}Delete\(\)/ nocase

    condition:
        filesize < 20MB and any of them
}
