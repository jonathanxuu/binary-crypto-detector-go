#!/usr/bin/env python3
"""Extract portable binary metadata with LIEF for the Go detector."""

import json
import sys
from pathlib import Path


CRYPTO_SYMBOL_MARKERS = (
    "aes", "chacha20", "poly1305", "blake2", "sha1", "sha2", "hmac",
    "rsa", "p256", "ecdsa", "x25519", "curve25519", "ed25519",
    "ml_kem", "mlkem", "ml_dsa", "mldsa", "slh_dsa", "slhdsa",
)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: lief-analyzer.py BINARY", file=sys.stderr)
        return 2

    try:
        import lief
    except ImportError:
        print("LIEF is not installed; run: python3 -m pip install lief", file=sys.stderr)
        return 3

    path = Path(sys.argv[1])
    binary = lief.parse(str(path))
    if binary is None:
        print(f"LIEF could not parse {path}", file=sys.stderr)
        return 4

    libraries = sorted({library.name for library in binary.libraries})
    imports = sorted({function.name for function in binary.imported_functions if function.name})
    symbols = sorted({symbol.name for symbol in binary.symbols if symbol.name})
    crypto_symbols = [
        symbol for symbol in symbols
        if any(marker in symbol.lower() for marker in CRYPTO_SYMBOL_MARKERS)
    ]
    result = {
        "format": str(binary.format).split(".")[-1],
        "libraries": libraries,
        "imports": imports,
        "crypto_symbols": crypto_symbols,
    }
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
