#!/usr/bin/env python3
"""
tls_extract.py
~~~~~~~~~~~~~~~~~~~
Recupera los certificados TLS de servicios .onion que usen HTTPS y los
muestra con información detallada (fingerprints, sujeto, emisor, fechas,
algoritmos, SAN, Key Usage, Extended KU, flag CA, etc.).

Requisitos:
    pip install pysocks ujson cryptography
    # y Tor escuchando en 127.0.0.1:9050
"""

# ──────────────────── IMPORTS ────────────────────
import ssl
import socket
import socks
import pathlib
import warnings
from urllib.parse import urlparse
from datetime import datetime

# JSON rápido
try:
    import ujson as json
except ModuleNotFoundError:
    import json

# X.509 análisis
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID
from cryptography.utils import CryptographyDeprecationWarning

# ───── SILENCIAR ADVERTENCIAS MOLESTAS ─────
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

# ─────────────────── CONFIG ────────────────────
TOR_HOST, TOR_PORT = "127.0.0.1", 9050  # proxy Tor local
INPUT_FILE = "resultados-array.json"    # fichero con URLs
TIMEOUT = 30                            # seg. para handshake
RETRIES = 2                             # reintentos si timeout
# ────────────────────────────────────────────────


# ╭───────────────── FUNCIONES UTILIDAD ─────────────────╮
def load_json(path: str):
    """Carga JSON array o JSONL; devuelve lista de dicts."""
    p = pathlib.Path(path)
    try:  # intenta JSON array
        with p.open("rb") as f:
            return json.load(f)
    except Exception:
        data = []
        with p.open("rb") as f:  # fallback a JSONL
            for ln in f:
                ln = ln.strip()
                if ln:
                    try:
                        data.append(json.loads(ln))
                    except Exception:
                        pass
        return data


def fp_hex_to_colon(hexstr: str, length: int) -> str:
    """Convierte 'aabbcc…' → 'aa:bb:cc', truncado a length*2 chars."""
    h = hexstr[:length]
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def get_ext(cert, oid):
    """Devuelve extensión X.509 o None si no existe."""
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None
# ╰──────────────────────────────────────────────────────╯


# ╭───────────────── DECODIFICAR CERT ─────────────────╮
def der_to_info(der: bytes):
    """Extrae campos interesantes de un certificado DER."""
    cert = x509.load_der_x509_certificate(der, default_backend())

    pub = cert.public_key()
    pub_alg = pub.__class__.__name__
    pub_bits = getattr(pub, "key_size", "-")

    san = get_ext(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    sans = san.get_values_for_type(x509.DNSName) if san else []

    ku = get_ext(cert, ExtensionOID.KEY_USAGE)
    eku = get_ext(cert, ExtensionOID.EXTENDED_KEY_USAGE)
    bc = get_ext(cert, ExtensionOID.BASIC_CONSTRAINTS)

    # Lista legible de Key Usage
    key_usage = []
    if ku:
        basic_flags = [
            "digital_signature", "content_commitment", "key_encipherment",
            "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign"
        ]
        for flag in basic_flags:
            if getattr(ku, flag):
                key_usage.append(flag)

        # encipher_only / decipher_only solo válidos si key_agreement=True
        if ku.key_agreement:
            if ku.encipher_only:
                key_usage.append("encipher_only")
            if ku.decipher_only:
                key_usage.append("decipher_only")

    return {
        "fp_sha1": fp_hex_to_colon(cert.fingerprint(hashes.SHA1()).hex(), 12),
        "fp_sha256": fp_hex_to_colon(cert.fingerprint(hashes.SHA256()).hex(), 16),
        "serial": hex(cert.serial_number),
        "version": cert.version.name,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "pub_alg": pub_alg,
        "pub_bits": pub_bits,
        "sig_alg": cert.signature_algorithm_oid._name,
        "sig_hash": cert.signature_hash_algorithm.name,
        "sans": sans,
        "is_ca": (bc.ca if bc else False),
        "key_usage": key_usage,
        "ext_ku": [e._name for e in eku] if eku else [],
    }
# ╰─────────────────────────────────────────────────────╯


# ╭───────────────── TLS VIA TOR ─────────────────╮
def get_tls_cert(host: str, timeout: int = TIMEOUT):
    """Devuelve info de cert o {'error': …}."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, TOR_HOST, TOR_PORT, rdns=True)
    s = socks.socksocket()
    s.settimeout(timeout)

    try:
        s.connect((host, 443))
        with ctx.wrap_socket(s, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            return der_to_info(der)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    finally:
        try:
            s.close()
        except Exception:
            pass
# ╰────────────────────────────────────────────────────╯


# ╭───────────── FILTRAR HOSTS HTTPS ─────────────╮
def onion_https_hosts(records):
    """Devuelve lista (con duplicados) de hosts .onion que usen https://."""
    hosts = []
    for r in records:
        url = r.get("final_url", "")
        if url.startswith("https://") and ".onion" in url.lower():
            hosts.append(urlparse(url).hostname.lower())
    return hosts
# ╰───────────────────────────────────────────────╯


# ╭──────────── IMPRESIÓN FORMATEADA ─────────────╮
def show(host: str, info: dict):
    """Imprime bonito el resultado o el error."""
    print(f"[~] TLS → {host}")
    if "error" in info:
        print(f"    ✗ {info['error']}\n")
        return

    print(f"    ✓ fp (SHA-256/16): {info['fp_sha256']}")
    print(f"      fp (SHA-1/6)   : {info['fp_sha1']}")
    print(f"      serial         : {info['serial']}   version: {info['version']}")
    print(f"      subject        : {info['subject']}")
    print(f"      issuer         : {info['issuer']}")
    print(f"      valid UTC      : {info['not_before']}  →  {info['not_after']}")
    print(f"      pubkey         : {info['pub_alg']} {info['pub_bits']}-bit")
    print(f"      sig alg/hash   : {info['sig_alg']} / {info['sig_hash']}")
    if info["sans"]:
        print(f"      SANs           : {', '.join(info['sans'])}")
    if info["key_usage"]:
        print(f"      Key Usage      : {', '.join(info['key_usage'])}")
    if info["ext_ku"]:
        print(f"      Ext Key Usage  : {', '.join(info['ext_ku'])}")
    if info["is_ca"]:
        print("      * Este certificado declara CA=TRUE *")
    print()
# ╰───────────────────────────────────────────────╯


def main():
    t0 = datetime.utcnow()
    print(f"[*] {t0.isoformat()} – Cargando '{INPUT_FILE}'…")
    records = load_json(INPUT_FILE)
    hosts = onion_https_hosts(records)
    print(f"[+] {len(hosts)} hosts .onion con HTTPS.\n")

    for host in hosts:
        # Reintento en caso de timeout del handshake
        attempt = 0
        while attempt <= RETRIES:
            result = get_tls_cert(host)
            if "error" not in result or "timeout" not in result["error"].lower():
                break
            attempt += 1
        show(host, result)

    dt = datetime.utcnow() - t0
    print(f"✓ Terminado en {dt.total_seconds():.1f}s")


if __name__ == "__main__":
    main()
