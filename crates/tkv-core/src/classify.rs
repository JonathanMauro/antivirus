//! Classificação de ameaças por categoria.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCategory {
    /// Arquivos de teste inofensivos (ex.: EICAR).
    Test,
    Trojan,
    Ransomware,
    Worm,
    Backdoor,
    /// Spyware, keyloggers e ladrões de credenciais.
    Spyware,
    Adware,
    /// Programa potencialmente indesejado.
    Pua,
    HackTool,
    Exploit,
    /// Downloaders e droppers (baixam/instalam outras ameaças).
    Downloader,
    /// Sem categoria específica (ex.: detecção apenas heurística).
    Generic,
}

impl ThreatCategory {
    pub const ALL: [ThreatCategory; 12] = [
        Self::Test,
        Self::Trojan,
        Self::Ransomware,
        Self::Worm,
        Self::Backdoor,
        Self::Spyware,
        Self::Adware,
        Self::Pua,
        Self::HackTool,
        Self::Exploit,
        Self::Downloader,
        Self::Generic,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Test => "test",
            Self::Trojan => "trojan",
            Self::Ransomware => "ransomware",
            Self::Worm => "worm",
            Self::Backdoor => "backdoor",
            Self::Spyware => "spyware",
            Self::Adware => "adware",
            Self::Pua => "pua",
            Self::HackTool => "hack_tool",
            Self::Exploit => "exploit",
            Self::Downloader => "downloader",
            Self::Generic => "generic",
        }
    }

    /// Nome amigável em português.
    pub fn label(self) -> &'static str {
        match self {
            Self::Test => "Arquivo de teste",
            Self::Trojan => "Cavalo de Troia",
            Self::Ransomware => "Ransomware",
            Self::Worm => "Worm",
            Self::Backdoor => "Backdoor / acesso remoto",
            Self::Spyware => "Spyware / roubo de dados",
            Self::Adware => "Adware",
            Self::Pua => "Programa indesejado",
            Self::HackTool => "Ferramenta de ataque",
            Self::Exploit => "Exploit",
            Self::Downloader => "Downloader / dropper",
            Self::Generic => "Genérico",
        }
    }

    /// Interpreta o identificador exato (`as_str`).
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().to_ascii_lowercase();
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }

    /// Deduz a categoria a partir de um nome de ameaça ou categoria livre,
    /// seguindo convenções comuns (ex.: "Trojan.Win32.X", "Ransom:Win32/Y").
    pub fn infer(name: &str) -> Option<Self> {
        if let Some(c) = Self::parse(name) {
            return Some(c);
        }
        let n = name.to_ascii_lowercase();
        let has = |keys: &[&str]| keys.iter().any(|k| n.contains(k));
        Some(if has(&["eicar", "test-file", "testfile"]) {
            Self::Test
        } else if has(&["ransom", "crypt0", "locker"]) {
            Self::Ransomware
        } else if has(&["backdoor", "rat.", "rat:", "remoteaccess"]) {
            Self::Backdoor
        } else if has(&["spy", "stealer", "keylog", "pws", "infostealer"]) {
            Self::Spyware
        } else if has(&["worm"]) {
            Self::Worm
        } else if has(&["downloader", "dropper", "loader"]) {
            Self::Downloader
        } else if has(&["exploit", "cve-"]) {
            Self::Exploit
        } else if has(&["hacktool", "hack_tool", "hack tool"]) {
            Self::HackTool
        } else if has(&["adware"]) {
            Self::Adware
        } else if has(&["pua", "pup", "riskware", "unwanted"]) {
            Self::Pua
        } else if has(&["trojan"]) {
            Self::Trojan
        } else {
            return None;
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for c in ThreatCategory::ALL {
            assert_eq!(ThreatCategory::parse(c.as_str()), Some(c));
        }
    }

    #[test]
    fn infers_from_common_names() {
        use ThreatCategory::*;
        assert_eq!(ThreatCategory::infer("EICAR-Test-File"), Some(Test));
        assert_eq!(ThreatCategory::infer("Ransom:Win32/WannaCrypt"), Some(Ransomware));
        assert_eq!(ThreatCategory::infer("Trojan.Win32.Agent"), Some(Trojan));
        assert_eq!(ThreatCategory::infer("Win32.Stealer.Redline"), Some(Spyware));
        assert_eq!(ThreatCategory::infer("TrojanDownloader:Win32/X"), Some(Downloader));
        assert_eq!(ThreatCategory::infer("algo qualquer"), None);
    }
}
