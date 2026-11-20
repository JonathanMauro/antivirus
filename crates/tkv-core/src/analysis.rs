//! Extração de características de um arquivo em uma única leitura.
//!
//! O arquivo é lido em blocos (streaming), então o consumo de memória é
//! constante independentemente do tamanho do arquivo.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Quantidade de bytes iniciais guardados para análise de cabeçalho.
pub const HEADER_LEN: usize = 4096;
const BUFFER_LEN: usize = 64 * 1024;

/// Características estáticas de um conteúdo analisado.
#[derive(Debug, Clone)]
pub struct FileFacts {
    pub size: u64,
    /// SHA-256 em hexadecimal minúsculo.
    pub sha256: String,
    /// Entropia de Shannon em bits por byte (0.0 a 8.0).
    pub entropy: f64,
    /// Primeiros bytes do conteúdo (até [`HEADER_LEN`]).
    pub header: Vec<u8>,
}

impl FileFacts {
    /// Indica se o conteúdo começa com a assinatura "MZ" de executáveis Windows (PE).
    pub fn is_pe(&self) -> bool {
        self.header.starts_with(b"MZ")
    }
}

/// Acumulador incremental de hash, histograma e cabeçalho.
struct Accumulator {
    hasher: Sha256,
    histogram: [u64; 256],
    header: Vec<u8>,
    size: u64,
}

impl Accumulator {
    fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            histogram: [0; 256],
            header: Vec::with_capacity(HEADER_LEN),
            size: 0,
        }
    }

    fn update(&mut self, chunk: &[u8]) {
        self.hasher.update(chunk);
        for &b in chunk {
            self.histogram[b as usize] += 1;
        }
        if self.header.len() < HEADER_LEN {
            let missing = HEADER_LEN - self.header.len();
            self.header.extend_from_slice(&chunk[..missing.min(chunk.len())]);
        }
        self.size += chunk.len() as u64;
    }

    fn finish(self) -> FileFacts {
        FileFacts {
            size: self.size,
            sha256: hex::encode(self.hasher.finalize()),
            entropy: shannon_entropy(&self.histogram, self.size),
            header: self.header,
        }
    }
}

/// Analisa um arquivo do disco.
pub fn analyze_file(path: &Path) -> Result<FileFacts> {
    let mut file = File::open(path).map_err(|e| Error::io(path, e))?;
    let mut acc = Accumulator::new();
    let mut buf = vec![0u8; BUFFER_LEN];
    loop {
        let n = file.read(&mut buf).map_err(|e| Error::io(path, e))?;
        if n == 0 {
            break;
        }
        acc.update(&buf[..n]);
    }
    Ok(acc.finish())
}

/// Analisa um conteúdo já carregado em memória.
pub fn analyze_bytes(data: &[u8]) -> FileFacts {
    let mut acc = Accumulator::new();
    acc.update(data);
    acc.finish()
}

/// Calcula apenas o SHA-256 de um arquivo.
pub fn sha256_file(path: &Path) -> Result<String> {
    analyze_file(path).map(|f| f.sha256)
}

/// Entropia de Shannon a partir de um histograma de bytes.
pub fn shannon_entropy(histogram: &[u64; 256], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let total = total as f64;
    histogram
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        let facts = analyze_bytes(b"abc");
        assert_eq!(
            facts.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(facts.size, 3);
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(analyze_bytes(&[0u8; 1000]).entropy, 0.0);
        let uniform: Vec<u8> = (0..=255u8).cycle().take(256 * 16).collect();
        assert!((analyze_bytes(&uniform).entropy - 8.0).abs() < 1e-9);
        assert_eq!(analyze_bytes(&[]).entropy, 0.0);
    }

    #[test]
    fn header_is_truncated() {
        let data = vec![7u8; HEADER_LEN * 3];
        assert_eq!(analyze_bytes(&data).header.len(), HEADER_LEN);
    }

    #[test]
    fn file_and_bytes_agree() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("amostra.bin");
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &data).unwrap();
        let from_file = analyze_file(&path).unwrap();
        let from_mem = analyze_bytes(&data);
        assert_eq!(from_file.sha256, from_mem.sha256);
        assert_eq!(from_file.size, from_mem.size);
        assert_eq!(from_file.header, from_mem.header);
    }
}
