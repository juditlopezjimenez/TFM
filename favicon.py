#!/usr/bin/env python3
"""
favicon.py – MD5 + Murmur3 de favicons (.onion) filtrando solo
registros con response_code == 200.  Compatible con Python 3.8+.

Requisitos:
    pip install "requests[socks]" ujson mmh3 tqdm
    # Tor escuchando en 127.0.0.1:9050
"""

import base64, csv, hashlib, json, pathlib, struct, sys
from typing import Dict, List, Union, Optional
from urllib.parse import urlparse

import mmh3, requests
from tqdm import tqdm

JSON_PATH = "resultados-array.json"
OUT_CSV   = "favicons_hashes.csv"
TOR_PROXY = "socks5h://127.0.0.1:9050"
TIMEOUT   = 20

# ───────────── helpers ──────────────────────────────────────────────────────
def load_json_any(path: Union[str, pathlib.Path]) -> List[Dict]:
    path = pathlib.Path(path)
    try:
        with path.open("rb") as f:
            return json.load(f)
    except (json.JSONDecodeError, ValueError):
        data: List[Dict] = []
        with path.open("rb") as f:
            for n, line in enumerate(f, 1):
                if not (line := line.strip()):
                    continue
                try:
                    data.append(json.loads(line))
                except (json.JSONDecodeError, ValueError):
                    print(f"[!] Línea {n} ignorada (JSON no válido)", file=sys.stderr)
        return data


def download_favicon(base_url: str, session: requests.Session) -> Optional[bytes]:
    try:
        p = urlparse(base_url)
        url = f"{p.scheme or 'http'}://{(p.netloc or p.path).rstrip('/')}/favicon.ico"
        r = session.get(url, timeout=TIMEOUT, verify=False)
        r.raise_for_status()
        return r.content or None
    except Exception:
        return None


def murmur3_from_bytes(blob: bytes) -> int:
    return mmh3.hash(base64.b64encode(blob))

# ───────────── main ────────────────────────────────────────────────────────
def main() -> None:
    raw = load_json_any(JSON_PATH)
    ok  = [o for o in raw if o.get("response_code") == 200]
    urls = sorted({o.get("final_url") or o.get("url") for o in ok})

    s = requests.Session()
    s.proxies = {"http": TOR_PROXY, "https": TOR_PROXY}
    s.headers.update({"User-Agent": "Mozilla/5.0"})

    rows = [("url","md5_hex","murmur3_int","shodan_query","censys_query","fofa_query")]

    for url in tqdm(urls, desc="Favicons"):
        blob = download_favicon(url, s)
        if not blob:
            continue
        md5_hex = hashlib.md5(blob).hexdigest()
        mur     = murmur3_from_bytes(blob)

        rows.append(
            (
                url,
                md5_hex,
                mur,
                f"http.favicon.hash:{mur}",
                f"services.http.favicon_hash:{mur}",
                f'icon_hash="{mur}"'
            )
        )

    pathlib.Path(OUT_CSV).write_text(
        "\n".join(",".join(map(str,r)) for r in rows), encoding="utf-8"
    )
    print(f"\n✓ {len(rows)-1} favicons procesados (código 200). CSV → {OUT_CSV}")


if __name__ == "__main__":
    main()
