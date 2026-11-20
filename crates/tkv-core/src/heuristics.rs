//! Heurísticas estáticas simples.
//!
//! Cada heurística produz um [`Indicator`] com uma pontuação. A soma
//! compõe o Risk Score. Os pesos são iniciais e PRECISAM ser calibrados
//! com dados reais para controlar falsos positivos.

use std::path::Path;

use serde::Serialize;

use crate::analysis::FileFacts;
use crate::pe::PeInfo;

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
/// `pe` traz a análise estrutural quando o conteúdo é um executável válido.
pub fn evaluate(file_name: Option<&str>, facts: &FileFacts, pe: Option<&PeInfo>) -> Vec<Indicator> {
    let mut out = Vec::new();
    if let Some(name) = file_name {
        if let Some(ind) = double_extension(name) {
            out.push(ind);
        }
        if let Some(ind) = disguised_pe(name, facts) {
            out.push(ind);
        }
    }
    match pe {
        // Com a estrutura PE disponível, a análise por seção substitui a
        // entropia do arquivo inteiro (mais precisa, menos falsos positivos).
        Some(pe) => out.extend(pe_indicators(pe)),
        None => out.extend(packed_executable(facts)),
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

/// Nomes de seção deixados por empacotadores/protetores conhecidos.
const PACKER_SECTIONS: &[(&str, &str)] = &[
    ("UPX0", "UPX"),
    ("UPX1", "UPX"),
    ("UPX2", "UPX"),
    (".aspack", "ASPack"),
    (".adata", "ASPack"),
    (".MPRESS1", "MPRESS"),
    (".MPRESS2", "MPRESS"),
    (".themida", "Themida"),
    (".winlice", "WinLicense"),
    (".vmp0", "VMProtect"),
    (".vmp1", "VMProtect"),
    (".vmp2", "VMProtect"),
    ("PEC2", "PECompact"),
    ("PEC2TO", "PECompact"),
    (".petite", "Petite"),
    (".nsp0", "NsPack"),
    (".nsp1", "NsPack"),
    (".enigma1", "Enigma"),
    (".enigma2", "Enigma"),
];

/// Funções usadas para injetar código em outro processo.
const INJECT_ALLOC: &[&str] = &["VirtualAllocEx", "NtAllocateVirtualMemory"];
const INJECT_WRITE: &[&str] = &["WriteProcessMemory", "NtWriteVirtualMemory"];
const INJECT_EXEC: &[&str] = &[
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "NtCreateThreadEx",
    "RtlCreateUserThread",
    "QueueUserAPC",
    "SetThreadContext",
];
const HOLLOW_UNMAP: &[&str] = &["NtUnmapViewOfSection", "ZwUnmapViewOfSection"];
const HOLLOW_RESUME: &[&str] = &["SetThreadContext", "ResumeThread"];
const KEY_HOOK: &[&str] = &["SetWindowsHookExA", "SetWindowsHookExW"];
const KEY_STATE: &[&str] = &["GetAsyncKeyState", "GetKeyboardState"];

/// Heurísticas sobre a estrutura de um executável PE.
pub fn pe_indicators(pe: &PeInfo) -> Vec<Indicator> {
    let mut out = Vec::new();

    // Empacotador conhecido (também usado legitimamente; sinal moderado).
    if let Some((section, packer)) = PACKER_SECTIONS
        .iter()
        .find(|(name, _)| pe.sections.iter().any(|s| s.name.eq_ignore_ascii_case(name)))
    {
        out.push(Indicator {
            id: "packer_section",
            description: format!("compactado com {packer} (seção '{section}')"),
            score: 25,
        });
    }

    // Seção executável com entropia alta: código cifrado/compactado.
    if let Some(s) = pe
        .sections
        .iter()
        .filter(|s| s.executable && s.raw_size > 0 && s.entropy > HIGH_ENTROPY_THRESHOLD)
        .max_by(|a, b| a.entropy.total_cmp(&b.entropy))
    {
        out.push(Indicator {
            id: "high_entropy_code",
            description: format!(
                "seção de código '{}' com entropia {:.2} (possível código cifrado)",
                s.name, s.entropy
            ),
            score: 20,
        });
    }

    // Seção ao mesmo tempo gravável e executável (código que se modifica).
    if let Some(s) = pe.sections.iter().find(|s| s.executable && s.writable) {
        out.push(Indicator {
            id: "wx_section",
            description: format!("seção '{}' gravável e executável", s.name),
            score: 15,
        });
    }

    // Ponto de entrada fora das seções ou em seção não executável.
    if pe.entry_point != 0 {
        match pe.entry_section {
            None => out.push(Indicator {
                id: "entry_outside_sections",
                description: "ponto de entrada fora de todas as seções".into(),
                score: 25,
            }),
            Some(i) if !pe.sections[i].executable => out.push(Indicator {
                id: "entry_in_data_section",
                description: format!(
                    "ponto de entrada em seção não executável ('{}')",
                    pe.sections[i].name
                ),
                score: 25,
            }),
            _ => {}
        }
    }

    // Tabela de importação vazia ou mínima (comum em executáveis compactados).
    // Assemblies .NET importam só mscoree.dll e são ignorados aqui.
    if !pe.is_dotnet && !pe.is_dll {
        let n = pe.imports.len();
        if n == 0 {
            out.push(Indicator {
                id: "no_imports",
                description: "executável sem funções importadas".into(),
                score: 15,
            });
        } else if n <= 3 {
            out.push(Indicator {
                id: "minimal_imports",
                description: format!("apenas {n} função(ões) importada(s)"),
                score: 10,
            });
        }
    }

    // Combinações de API associadas a técnicas de ataque. Só valem para
    // executáveis: DLLs do sistema (ex.: kernel32.dll) importam essas funções
    // para repassá-las a outros programas, o que geraria falsos positivos.
    if !pe.is_dll {
        out.extend(api_combo_indicators(pe));
    }

    out
}

fn api_combo_indicators(pe: &PeInfo) -> Vec<Indicator> {
    let mut out = Vec::new();
    if pe.imports_any(INJECT_ALLOC) && pe.imports_any(INJECT_WRITE) && pe.imports_any(INJECT_EXEC) {
        out.push(Indicator {
            id: "process_injection",
            description: "importa funções para injetar código em outros processos".into(),
            score: 35,
        });
    }
    if pe.imports_any(HOLLOW_UNMAP) && pe.imports_any(HOLLOW_RESUME) {
        out.push(Indicator {
            id: "process_hollowing",
            description: "importa funções usadas em 'process hollowing'".into(),
            score: 30,
        });
    }
    if pe.imports_any(KEY_HOOK) && pe.imports_any(KEY_STATE) {
        out.push(Indicator {
            id: "keylogger_apis",
            description: "importa funções de captura de teclado".into(),
            score: 20,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::analyze_bytes;
    use crate::pe::{ImportInfo, SectionInfo};

    fn section(name: &str, entropy: f64, exec: bool, write: bool) -> SectionInfo {
        SectionInfo {
            name: name.into(),
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            raw_size: 0x1000,
            entropy,
            executable: exec,
            writable: write,
        }
    }

    fn pe_with(sections: Vec<SectionInfo>, imports: &[&str]) -> PeInfo {
        PeInfo {
            is_64: true,
            is_dll: false,
            timestamp: 0,
            entry_point: 0x1100,
            entry_section: Some(0),
            sections,
            imports: imports
                .iter()
                .map(|f| ImportInfo {
                    dll: "kernel32.dll".into(),
                    function: (*f).into(),
                })
                .collect(),
            has_certificate: false,
            is_dotnet: false,
        }
    }

    fn ids(v: &[Indicator]) -> Vec<&'static str> {
        v.iter().map(|i| i.id).collect()
    }

    #[test]
    fn clean_pe_has_no_indicators() {
        let pe = pe_with(
            vec![section(".text", 6.2, true, false), section(".data", 3.0, false, true)],
            &["CreateFileW", "ReadFile", "CloseHandle", "ExitProcess"],
        );
        assert!(pe_indicators(&pe).is_empty());
    }

    #[test]
    fn detects_packer_entropy_and_wx() {
        let pe = pe_with(
            vec![section("UPX0", 0.0, true, true), section("UPX1", 7.9, true, true)],
            &["LoadLibraryA", "GetProcAddress"],
        );
        let found = ids(&pe_indicators(&pe));
        assert!(found.contains(&"packer_section"));
        assert!(found.contains(&"high_entropy_code"));
        assert!(found.contains(&"wx_section"));
        assert!(found.contains(&"minimal_imports"));
    }

    #[test]
    fn detects_injection_and_keylogger() {
        let pe = pe_with(
            vec![section(".text", 6.0, true, false)],
            &[
                "VirtualAllocEx",
                "WriteProcessMemory",
                "CreateRemoteThread",
                "SetWindowsHookExW",
                "GetAsyncKeyState",
            ],
        );
        let found = ids(&pe_indicators(&pe));
        assert!(found.contains(&"process_injection"));
        assert!(found.contains(&"keylogger_apis"));
    }

    #[test]
    fn api_combos_ignored_in_dlls() {
        // Caso real: kernel32.dll importa estas funções para reexportá-las.
        let mut pe = pe_with(
            vec![section(".text", 6.3, true, false)],
            &[
                "VirtualAllocEx",
                "WriteProcessMemory",
                "CreateRemoteThread",
                "NtUnmapViewOfSection",
                "ResumeThread",
            ],
        );
        pe.is_dll = true;
        assert!(pe_indicators(&pe).is_empty());
    }

    #[test]
    fn entry_point_anomalies() {
        let mut pe = pe_with(
            vec![section(".text", 6.0, true, false), section(".data", 3.0, false, true)],
            &["A", "B", "C", "D"],
        );
        pe.entry_section = Some(1);
        assert!(ids(&pe_indicators(&pe)).contains(&"entry_in_data_section"));
        pe.entry_section = None;
        assert!(ids(&pe_indicators(&pe)).contains(&"entry_outside_sections"));
    }

    #[test]
    fn dotnet_is_not_flagged_for_few_imports() {
        let mut pe = pe_with(vec![section(".text", 6.0, true, false)], &["_CorExeMain"]);
        assert!(ids(&pe_indicators(&pe)).contains(&"minimal_imports"));
        pe.is_dotnet = true;
        assert!(pe_indicators(&pe).is_empty());
    }

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
