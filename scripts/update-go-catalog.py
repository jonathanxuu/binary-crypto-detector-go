#!/usr/bin/env python3
"""Discover crypto packages available in the local Go toolchain/modules.

The detector consumes the generated catalog; package discovery is kept here so
adding a new Go release or x/crypto module does not require changing Go code.
"""

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PACKAGE_ALGORITHMS = {
    "aes": ("AES", "encryption"),
    "sha1": ("SHA-1", "digest"),
    "sha256": ("SHA-256", "digest"),
    "sha512": ("SHA-512", "digest"),
    "hmac": ("HMAC", "message authentication"),
    "rsa": ("RSA", "public-key cryptography"),
    "ecdsa": ("ECDSA", "signature"),
    "ecdh": ("X25519", "key agreement"),
    "mlkem": ("ML-KEM", "key encapsulation"),
    "chacha20poly1305": ("ChaCha20-Poly1305", "AEAD encryption"),
    "blake2b": ("BLAKE2b-512", "digest"),
}


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def add_package(entries, library, source, package_path, package_dir):
    package = package_dir.name
    mapping = PACKAGE_ALGORITHMS.get(package)
    if mapping is None:
        return
    algorithm, purpose = mapping
    safe = package_path.replace("/", ".").replace("-", "_")
    symbols = [package_path, package]
    if library == "Go standard library":
        symbols.extend([f"crypto/internal/fips140/{package}"])
    entries.append({
        "id": f"go.{safe}",
        "rule": f"Go_{safe}",
        "algorithm": algorithm,
        "purpose": purpose,
        "imports": [],
        "symbols": symbols,
        "evidence": symbols,
        "yara_strings": [],
        "library": library,
        "source": source,
    })


def main():
    goroot = Path(command("go", "env", "GOROOT"))
    entries = []
    stdlib = goroot / "src" / "crypto"
    for package_dir in sorted(stdlib.iterdir()):
        if package_dir.is_dir():
            add_package(entries, "Go standard library", str(stdlib), f"crypto/{package_dir.name}", package_dir)

    gopath = Path(command("go", "env", "GOPATH"))
    module_root = gopath / "pkg" / "mod" / "golang.org" / "x"
    for package_dir in sorted(module_root.glob("crypto@*/")):
        for child in sorted(package_dir.iterdir()):
            if child.is_dir():
                add_package(entries, "golang.org/x/crypto", str(package_dir), f"golang.org/x/crypto/{child.name}", child)

    output = {"library": "Go", "source": "Go toolchain and installed modules", "algorithms": entries}
    path = ROOT / "catalog" / "go-official.json"
    path.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n")
    print(f"discovered {len(entries)} Go crypto package mappings -> {path}")


if __name__ == "__main__":
    main()
