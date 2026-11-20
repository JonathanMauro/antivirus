//! Análise estática de executáveis Windows (formato PE).

use goblin::pe::section_table::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};
use goblin::pe::PE;
use serde::Serialize;

use crate::analysis::entropy_of;

#[derive(Debug, Clone, Serialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub entropy: f64,
    pub executable: bool,
    pub writable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportInfo {
    /// Nome da DLL em minúsculas (ex.: "kernel32.dll").
    pub dll: String,
    /// Nome da função; vazio quando importada por ordinal.
    pub function: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeInfo {
    pub is_64: bool,
    pub is_dll: bool,
    pub timestamp: u32,
    pub entry_point: u32,
    /// Índice da seção que contém o ponto de entrada.
    pub entry_section: Option<usize>,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<ImportInfo>,
    /// Possui tabela de certificados (assinatura Authenticode presente,
    /// mas NÃO verificada).
    pub has_certificate: bool,
    /// Assembly .NET (código gerenciado; importa quase só mscoree.dll).
    pub is_dotnet: bool,
}

impl PeInfo {
    pub fn imports_function(&self, name: &str) -> bool {
        self.imports
            .iter()
            .any(|i| i.function.eq_ignore_ascii_case(name))
    }

    pub fn imports_any(&self, names: &[&str]) -> bool {
        names.iter().any(|n| self.imports_function(n))
    }
}

/// Faz o parsing de um PE. Retorna `None` se o conteúdo não for um PE válido.
pub fn parse(data: &[u8]) -> Option<PeInfo> {
    let pe = PE::parse(data).ok()?;

    let sections: Vec<SectionInfo> = pe
        .sections
        .iter()
        .map(|s| {
            let start = s.pointer_to_raw_data as usize;
            let end = start.saturating_add(s.size_of_raw_data as usize).min(data.len());
            let raw = if start < end { &data[start..end] } else { &[][..] };
            SectionInfo {
                name: String::from_utf8_lossy(&s.name)
                    .trim_end_matches('\0')
                    .to_string(),
                virtual_address: s.virtual_address,
                virtual_size: s.virtual_size,
                raw_size: s.size_of_raw_data,
                entropy: entropy_of(raw),
                executable: s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
                writable: s.characteristics & IMAGE_SCN_MEM_WRITE != 0,
            }
        })
        .collect();

    let entry_point = pe.entry as u32;
    let entry_section = sections.iter().position(|s| {
        let size = s.virtual_size.max(s.raw_size);
        entry_point >= s.virtual_address && entry_point < s.virtual_address.saturating_add(size)
    });

    let imports = pe
        .imports
        .iter()
        .map(|i| ImportInfo {
            dll: i.dll.to_ascii_lowercase(),
            function: i.name.to_string(),
        })
        .collect();

    let dirs = pe.header.optional_header.as_ref().map(|oh| &oh.data_directories);
    let has_certificate = dirs
        .and_then(|d| d.get_certificate_table())
        .is_some_and(|d| d.size > 0);
    let is_dotnet = dirs
        .and_then(|d| d.get_clr_runtime_header())
        .is_some_and(|d| d.size > 0);

    Some(PeInfo {
        is_64: pe.is_64,
        is_dll: pe.is_lib,
        timestamp: pe.header.coff_header.time_date_stamp,
        entry_point,
        entry_section,
        sections,
        imports,
        has_certificate,
        is_dotnet,
    })
}
