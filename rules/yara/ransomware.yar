// Indícios de ransomware em arquivos (notas de resgate e similares).

rule Ransom_Note_Text
{
    meta:
        description = "texto típico de nota de resgate de ransomware"
        category = "ransomware"
        score = 45

    strings:
        $enc1 = "your files have been encrypted" nocase
        $enc2 = "all your files are encrypted" nocase
        $enc3 = "your important files are encrypted" nocase
        $enc4 = "seus arquivos foram criptografados" nocase
        $enc5 = "todos os seus arquivos foram" nocase

        $pay1 = "bitcoin" nocase
        $pay2 = "monero" nocase
        $pay3 = /\b(bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,39}\b/
        $pay4 = ".onion" nocase

        $dec1 = "decrypt" nocase
        $dec2 = "descriptograf" nocase
        $dec3 = "private key" nocase
        $dec4 = "chave privada" nocase

    condition:
        filesize < 2MB and any of ($enc*) and any of ($pay*) and any of ($dec*)
}
