#!/usr/bin/env python3
"""
favicon.py – MD5 + Murmur3 de favicons (.onion), integración con FOFA API (solo con API key)
"""

import base64, hashlib, json, pathlib, sys, time
from typing import Dict, List, Union, Optional
from urllib.parse import urlparse, quote

import mmh3, requests
from tqdm import tqdm

# ───── CONFIGURACIÓN ─────
JSON_PATH = "resultados-array.json"
OUT_CSV   = "favicons_hashes.csv"
TOR_PROXY = "socks5h://127.0.0.1:9050"
TIMEOUT   = 20

# CREDENCIAL FOFA – solo API key
FOFA_API_KEY = ""  # ← Rellena con tu API key
FOFA_API_URL = "https://fofa.info/api/v1/search/all"

# ───── FUNCIONES ─────
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
                except Exception:
                    print(f"[!] Línea {n} ignorada (JSON inválido)", file=sys.stderr)
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


def fofa_search(query: str) -> int:
    try:
        q_base64 = base64.b64encode(query.encode()).decode()
        url = f"{FOFA_API_URL}?key={FOFA_API_KEY}&qbase64={q_base64}&size=1"
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            data = r.json()
            return data.get("size", 0)
        else:
            print(f"[FOFA] Error HTTP {r.status_code} → {r.text}")
    except Exception as e:
        print(f"[FOFA] Error: {e}")
    return -1

# ───── MAIN ─────
def main() -> None:
    raw = load_json_any(JSON_PATH)
    ok  = [o for o in raw if o.get("response_code") == 200]
    urls = sorted({o.get("final_url") or o.get("url") for o in ok})

    s = requests.Session()
    s.proxies = {"http": TOR_PROXY, "https": TOR_PROXY}
    s.headers.update({"User-Agent": "Mozilla/5.0"})

    rows = [("url","md5_hex","murmur3_int","shodan_query","censys_query","fofa_query","fofa_hits")]

    for url in tqdm(urls, desc="Favicons"):
        blob = download_favicon(url, s)
        if not blob:
            continue
        md5_hex = hashlib.md5(blob).hexdigest()
        mur     = murmur3_from_bytes(blob)

        shodan_q = f"http.favicon.hash:{mur}"
        censys_q = f"services.http.favicon_hash:{mur}"
        fofa_q   = f'icon_hash="{mur}"'

        hits = fofa_search(fofa_q)
        time.sleep(1.2)  # evitar rate limit de FOFA

        rows.append((url, md5_hex, mur, shodan_q, censys_q, fofa_q, hits))

    pathlib.Path(OUT_CSV).write_text(
        "\n".join(",".join(map(str,r)) for r in rows), encoding="utf-8"
    )
    print(f"\n✓ {len(rows)-1} favicons procesados (código 200). CSV → {OUT_CSV}")


if __name__ == "__main__":
    main()
