rule Libsodium_X25519
{
    meta:
        library = "libsodium"
        algorithm = "X25519"
    strings:
        $a = "crypto_scalarmult_curve25519" ascii wide
    condition:
        1 of them
}

rule OpenSSL_SHA1
{
    meta:
        library = "OpenSSL"
        algorithm = "SHA-1"
    strings:
        $a = "SHA1" ascii wide
    condition:
        1 of them
}

rule OpenSSL_SHA256
{
    meta:
        library = "OpenSSL"
        algorithm = "SHA-256"
    strings:
        $a = "EVP_sha256" ascii wide
        $b = "SHA256_Init" ascii wide
        $c = "SHA256_Update" ascii wide
    condition:
        1 of them
}

rule OpenSSL_SHA512
{
    meta:
        library = "OpenSSL"
        algorithm = "SHA-512"
    strings:
        $a = "EVP_sha512" ascii wide
    condition:
        1 of them
}

rule OpenSSL_AES_256_GCM
{
    meta:
        library = "OpenSSL"
        algorithm = "AES-256-GCM"
    strings:
        $a = "EVP_aes_256_gcm" ascii wide
        $b = "AES-256-GCM" ascii wide
    condition:
        1 of them
}

rule OpenSSL_AES_128_CBC
{
    meta:
        library = "OpenSSL"
        algorithm = "AES-128-CBC"
    strings:
        $a = "EVP_aes_128_cbc" ascii wide
    condition:
        1 of them
}

rule OpenSSL_ChaCha20_Poly1305
{
    meta:
        library = "OpenSSL"
        algorithm = "ChaCha20-Poly1305"
    strings:
        $a = "EVP_chacha20_poly1305" ascii wide
    condition:
        1 of them
}

rule OpenSSL_BLAKE2B_512
{
    meta:
        library = "OpenSSL"
        algorithm = "BLAKE2b-512"
    strings:
        $a = "EVP_blake2b512" ascii wide
    condition:
        1 of them
}

rule OpenSSL_HMAC_SHA512
{
    meta:
        library = "OpenSSL"
        algorithm = "HMAC-SHA512"
    strings:
        $a = "HMAC-SHA512" ascii wide
    condition:
        1 of them
}

rule OpenSSL_RSA
{
    meta:
        library = "OpenSSL"
        algorithm = "RSA"
    strings:
        $a = "RSA_sign" ascii wide
        $b = "RSA_verify" ascii wide
    condition:
        1 of them
}

rule OpenSSL_RSA_PSS_SHA256
{
    meta:
        library = "OpenSSL"
        algorithm = "RSA-PSS-SHA256"
    strings:
        $a = "RSA-PSS-SHA256" ascii wide
    condition:
        1 of them
}

rule OpenSSL_RSA_OAEP_SHA256
{
    meta:
        library = "OpenSSL"
        algorithm = "RSA-OAEP-SHA256"
    strings:
        $a = "RSA-OAEP-SHA256" ascii wide
    condition:
        1 of them
}

rule OpenSSL_ECDSA
{
    meta:
        library = "OpenSSL"
        algorithm = "ECDSA"
    strings:
        $a = "ECDSA_sign" ascii wide
        $b = "ECDSA_verify" ascii wide
    condition:
        1 of them
}

rule OpenSSL_ECDSA_P256
{
    meta:
        library = "OpenSSL"
        algorithm = "ECDSA P-256"
    strings:
        $a = "ECDSA P-256" ascii wide
    condition:
        1 of them
}

rule OpenSSL_Ed25519
{
    meta:
        library = "OpenSSL"
        algorithm = "Ed25519"
    strings:
        $a = "EVP_PKEY_ED25519" ascii wide
        $b = "Ed25519" ascii wide
    condition:
        1 of them
}

rule OpenSSL_X25519
{
    meta:
        library = "OpenSSL"
        algorithm = "X25519"
    strings:
        $a = "X25519 key agreement" ascii wide
    condition:
        1 of them
}
