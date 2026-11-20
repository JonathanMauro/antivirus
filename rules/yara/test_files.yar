// Arquivos de teste inofensivos usados para validar a detecção.

rule EICAR_Test_File
{
    meta:
        description = "arquivo de teste antivírus EICAR (inofensivo)"
        category = "test"
        threat = "EICAR-Test-File"
        score = 100
        malicious = true

    strings:
        // Apenas o trecho central: a variante com espaços ou quebras de linha
        // extras também é reconhecida, mas este arquivo de regras não é
        // detectado como EICAR (o padrão exige o conteúdo no início do arquivo).
        $s = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

    condition:
        filesize < 256 and $s
}
