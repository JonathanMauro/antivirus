"""Extração de atributos estáticos de arquivos para Machine Learning.

Os mesmos atributos deverão ser reimplementados no motor Rust na Fase 4,
para que o modelo treinado aqui possa ser aplicado em tempo de varredura.
Por isso, mantenha a lista FEATURE_NAMES estável e documentada.

Uso:
    python -m tkv_ml.features <pasta> <saida.csv>
"""

from __future__ import annotations

import csv
import hashlib
import math
import sys
from collections import Counter
from pathlib import Path

import pefile

FEATURE_NAMES = [
    "size",
    "entropy",
    "is_pe",
    "num_sections",
    "max_section_entropy",
    "min_section_entropy",
    "num_executable_sections",
    "num_writable_executable_sections",
    "num_imported_dlls",
    "num_imported_functions",
    "has_debug",
    "has_resources",
    "has_signature",
    "is_dll",
]

# APIs frequentemente associadas a injeção, ofuscação ou ransomware.
# Presença NÃO significa malícia: programas legítimos também as usam.
SUSPICIOUS_IMPORTS = {
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "CryptEncrypt",
    "IsDebuggerPresent",
}
FEATURE_NAMES.append("num_suspicious_imports")

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in Counter(data).values())


def extract(path: Path) -> dict:
    data = path.read_bytes()
    feats = {name: 0 for name in FEATURE_NAMES}
    feats["size"] = len(data)
    feats["entropy"] = round(shannon_entropy(data), 6)

    if not data.startswith(b"MZ"):
        return feats

    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories()
    except pefile.PEFormatError:
        return feats

    feats["is_pe"] = 1
    feats["is_dll"] = int(pe.is_dll())

    sections = pe.sections
    feats["num_sections"] = len(sections)
    if sections:
        entropies = [s.get_entropy() for s in sections]
        feats["max_section_entropy"] = round(max(entropies), 6)
        feats["min_section_entropy"] = round(min(entropies), 6)
    for s in sections:
        ch = s.Characteristics
        if ch & IMAGE_SCN_MEM_EXECUTE:
            feats["num_executable_sections"] += 1
            if ch & IMAGE_SCN_MEM_WRITE:
                feats["num_writable_executable_sections"] += 1

    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        feats["num_imported_dlls"] += 1
        for imp in entry.imports:
            feats["num_imported_functions"] += 1
            if imp.name and imp.name.decode(errors="ignore") in SUSPICIOUS_IMPORTS:
                feats["num_suspicious_imports"] += 1

    feats["has_debug"] = int(hasattr(pe, "DIRECTORY_ENTRY_DEBUG"))
    feats["has_resources"] = int(hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"))
    sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    ]
    feats["has_signature"] = int(sec_dir.Size > 0)
    pe.close()
    return feats


def extract_folder(folder: Path, out_csv: Path) -> int:
    count = 0
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["path", "sha256", *FEATURE_NAMES])
        writer.writeheader()
        for path in folder.rglob("*"):
            if not path.is_file():
                continue
            try:
                feats = extract(path)
                sha = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError as exc:
                print(f"ignorado {path}: {exc}", file=sys.stderr)
                continue
            writer.writerow({"path": str(path), "sha256": sha, **feats})
            count += 1
    return count


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    n = extract_folder(Path(sys.argv[1]), Path(sys.argv[2]))
    print(f"{n} arquivo(s) processado(s)")
