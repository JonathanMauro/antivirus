//! Heurísticas estáticas simples.
//!
//! Cada heurística produz um [`Indicator`] com uma pontuação. A soma
//! compõe o Risk Score. Os pesos são iniciais e PRECISAM ser calibrados
//! com dados reais para controlar falsos positivos.

use std::path::Path;

use serde::Serialize;

use crate::analysis::FileFacts;

/// Entropia acima da qual um executável é considerado possivelmente compactado/cifrado.
pub const HIGH_ENTROPY_THRESHOLD: f64 = 7.2;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Indicator {
    pub id: &'static str,
    pub description: String,
    pub score: u8,
}

const EXECUTABLE_EXTS: &[&str] = &[
    "exe", "scr", "com", "pif", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta",
    "msi", "lnk",
];

const DECOY_EXTS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png",
    "gif", "bmp", "mp3", "mp4", "avi", "zip", "rar", "7z",
];

/// Extensões legítimas para conteúdo PE (começando com "MZ").
const PE_EXTS: &[&str] = &[
    "exe", "dll", "sys", "scr", "ocx", "cpl", "drv", "efi", "mui", "ax", "pyd", "node", "winmd",
    "com", "tlb", "acm", "tsp", "fon", "ime", "flt",
];

fn lower_ext(name: &str) -> Option<String> {
    Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
}

/// Executa todas as heurísticas sobre um arquivo.
/// `file_name` é apenas o nome (ex.: "fatura.pdf.exe"), se disponível.
pub fn evaluate(file_name: Option<&str>, facts: &FileFacts) -> Vec<Indicator> {
    let mut out = Vec::new();
    if let Some(name) = file_name {
        if let Some(ind) = double_extension(name) {
            out.push(ind);
        }
        if let Some(ind) = disguised_pe(name, facts) {
            out.push(ind);
        }
    }
    if let Some(ind) = packed_executable(facts) {
        out.push(ind);
    }
    out
}

/// "relatorio.pdf.exe": documento aparente que na verdade é executável.
pub fn double_extension(name: &str) -> Option<Indicator> {
    let lower = name.to_ascii_lowercase();
    let mut parts = lower.rsplit('.');
    let last = parts.next()?;
    let previous = parts.next()?;
    // Garante que existe um nome base antes da extensão falsa.
    if parts.next().is_none_or(str::is_empty) {
        return None;
    }
    if EXECUTABLE_EXTS.contains(&last) && DECOY_EXTS.contains(&previous) {
        Some(Indicator {
            id: "double_extension",
            description: format!("extensão dupla enganosa: '.{previous}.{last}'"),
            score: 45,
        })
    } else {
        None
    }
}

/// Conteúdo executável (PE) com extensão que não é de executável.
pub fn disguised_pe(name: &str, facts: &FileFacts) -> Option<Indicator> {
    if !facts.is_pe() {
        return None;
    }
    match lower_ext(name) {
        Some(ext) if PE_EXTS.contains(&ext.as_str()) => None,
        Some(ext) => Some(Indicator {
            id: "disguised_pe",
            description: format!("executável PE com extensão '.{ext}'"),
            score: 35,
        }),
        // Sem extensão: sinal fraco.
        None => Some(Indicator {
            id: "pe_without_extension",
            description: "executável PE sem extensão".into(),
            score: 10,
        }),
    }
}

/// Executável com entropia alta (possível packer/criptografia).
/// Muitos instaladores legítimos também são compactados: sinal moderado.
pub fn packed_executable(facts: &FileFacts) -> Option<Indicator> {
    if facts.is_pe() && facts.entropy > HIGH_ENTROPY_THRESHOLD {
        Some(Indicator {
            id: "high_entropy_pe",
            description: format!(
                "executável com entropia alta ({:.2} bits/byte), possivelmente compactado",
                facts.entropy
            ),
            score: 25,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::analyze_bytes;

    #[test]
    fn detects_double_extension() {
        assert!(double_extension("Fatura.PDF.exe").is_some());
        assert!(double_extension("foto.jpg.scr").is_some());
        assert!(double_extension("setup.exe").is_none());
        assert!(double_extension("backup.tar.gz").is_none());
        // ".pdf.exe" sem nome base não conta como duas extensões
        assert!(double_extension(".pdf.exe").is_none());
    }

    #[test]
    fn detects_disguised_pe() {
        let pe = analyze_bytes(b"MZ\x90\x00 restante do cabecalho");
        assert!(disguised_pe("imagem.jpg", &pe).is_some());
        assert!(disguised_pe("programa.exe", &pe).is_none());
        assert!(disguised_pe("biblioteca.DLL", &pe).is_none());

        let text = analyze_bytes(b"apenas texto");
        assert!(disguised_pe("imagem.jpg", &text).is_none());
    }

    #[test]
    fn detects_high_entropy_pe() {
        let mut data = b"MZ".to_vec();
        data.extend((0..=255u8).cycle().take(64 * 1024));
        assert!(packed_executable(&analyze_bytes(&data)).is_some());

        let low = analyze_bytes(&[b'M', b'Z', 0, 0, 0, 0, 0, 0]);
        assert!(packed_executable(&low).is_none());
    }
}
