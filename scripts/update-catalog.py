#!/usr/bin/env python3
"""Discover algorithm names/APIs from installed official crypto libraries.

The output is intentionally a discovery catalog, not a confirmed-usage catalog.
It is safe to merge into the detector as candidate knowledge only.
"""

import argparse
import json
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(command):
    try:
        return subprocess.run(command, check=True, capture_output=True, text=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return ""


def prefix_candidates(name):
    values = []
    explicit = os.environ.get(name)
    if explicit:
        values.append(Path(explicit))
    for root in (Path("/opt/homebrew/opt"), Path("/usr/local/opt"), Path("/usr")):
        values.append(root)
    return values


def find_prefix(package, env_name):
    explicit = os.environ.get(env_name)
    if explicit:
        return Path(explicit)
    brew = run(["brew", "--prefix", package]).strip()
    if brew:
        return Path(brew)
    for root in prefix_candidates(env_name):
        candidate = root / package
        if candidate.exists():
            return candidate
    return None


def openssl_algorithms(openssl_bin):
    if not openssl_bin:
        return []
    groups = {
        "digest": "digest-algorithms",
        "cipher": "cipher-algorithms",
        "mac": "mac-algorithms",
        "kdf": "kdf-algorithms",
        "signature": "signature-algorithms",
        "key_exchange": "key-exchange-algorithms",
        "kem": "kem-algorithms",
        "public_key": "public-key-algorithms",
    }
    entries = {}
    for purpose, option in groups.items():
        output = run([str(openssl_bin), "list", "-1", f"-{option}"])
        for raw in output.splitlines():
            line = raw.strip()
            if not line or line.endswith(":"):
                continue
            line = line.split(" @ ", 1)[0]
            names = re.findall(r"[A-Za-z][A-Za-z0-9_./+-]*", line)
            if not names:
                continue
            for name in names:
                if name.lower().startswith("id-") or name.lower().startswith("openssl"):
                    continue
                canonical = canonical_name(name)
                key = canonical.upper()
                item = entries.setdefault(key, {"algorithm": canonical, "aliases": [], "purpose": purpose, "imports": [], "source": "openssl list"})
                if name != canonical and name not in item["aliases"]:
                    item["aliases"].append(name)
                if purpose not in item["purpose"]:
                    item["purpose"] += "," + purpose
                api = openssl_api_guess(name)
                if api and api not in item["imports"]:
                    item["imports"].append(api)
    return list(entries.values())


def canonical_name(name):
    upper = name.upper()
    match = re.fullmatch(r"MLKEM[_-]?(512|768|1024)", upper)
    if match:
        return f"ML-KEM-{match.group(1)}"
    match = re.fullmatch(r"MLDSA[_-]?(44|65|87)", upper)
    if match:
        return f"ML-DSA-{match.group(1)}"
    match = re.fullmatch(r"SHA3[_-]?(224|256|384|512)", upper)
    if match:
        return f"SHA3-{match.group(1)}"
    match = re.fullmatch(r"SHA[_-]?(1|224|256|384|512)", upper)
    if match:
        return f"SHA-{match.group(1)}"
    match = re.fullmatch(r"BLAKE2B[_-]?(256|512)", upper)
    if match:
        return f"BLAKE2b-{match.group(1)}"
    if upper == "ED25519":
        return "Ed25519"
    if upper == "ED448":
        return "Ed448"
    return name


def openssl_api_guess(name):
    normalized = name.lower().replace("-", "_").replace("/", "_")
    if normalized.startswith(("aes_", "aria_", "camellia_", "chacha", "des_", "sm4_")):
        return "EVP_" + normalized
    if normalized.startswith(("sha", "sha3", "md", "blake", "sm3", "ripemd")):
        return "EVP_" + normalized
    return ""


def header_symbols(prefix, library):
    if not prefix:
        return []
    include = prefix / "include"
    if not include.exists():
        return []
    pattern = re.compile(r"\b(crypto_[a-zA-Z0-9_]+)\s*\(")
    purpose = "libsodium API"
    symbols = set()
    for path in include.rglob("*.h"):
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        symbols.update(pattern.findall(text))
    return [{"library": library, "algorithm": f"{library}:{symbol}", "purpose": purpose, "imports": [symbol], "source": str(include)} for symbol in sorted(symbols)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--openssl", default=os.environ.get("OPENSSL_BIN", "openssl"))
    parser.add_argument("--libsodium-prefix", default=None)
    args = parser.parse_args()

    openssl_bin = args.openssl
    if "OPENSSL_BIN" not in os.environ and args.openssl == "openssl":
        openssl_prefix = find_prefix("openssl@3", "OPENSSL_PREFIX")
        candidate = openssl_prefix / "bin" / "openssl" if openssl_prefix else None
        if candidate and candidate.exists():
            openssl_bin = str(candidate)
    openssl = openssl_algorithms(openssl_bin)
    for item in openssl:
        item["library"] = "OpenSSL"
    libsodium = header_symbols(Path(args.libsodium_prefix) if args.libsodium_prefix else find_prefix("libsodium", "LIBSODIUM_PREFIX"), "libsodium")
    output = {
        "generated_by": "scripts/update-catalog.py",
        "sources": {"openssl": openssl_bin, "libsodium": "public headers"},
        "algorithms": openssl + libsodium,
    }
    target = ROOT / "catalog" / "official-discovered.json"
    target.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n")
    print(f"discovered {len(output['algorithms'])} official library entries -> {target}")


if __name__ == "__main__":
    main()
