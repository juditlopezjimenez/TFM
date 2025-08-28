#!/usr/bin/env python3
"""
fingerprinting.py – Análisis de cabeceras HTTP (como los generados por gowitness, zgrab, etc.)

Requisitos:
    pip install ujson pandas datasketch tqdm
"""

import hashlib
import pathlib
import sys
from typing import Union, List, Dict, Set

# ────────── dependencias básicas ──────────
try:
    import ujson as json
except ModuleNotFoundError:
    import json

import pandas as pd
from tqdm import tqdm

# ────────── datasketch opcional ──────────
try:
    from datasketch import MinHash, MinHashLSH
except ModuleNotFoundError:
    print("[!] 'datasketch' no está instalado — se omite near-duplicate MinHash")
    MinHash = MinHashLSH = None

# ────────── configuración ──────────
PATH: str = "resultados-array.json"
OUT_DIR = pathlib.Path(".")
VOLATILES: Set[str] = {"date", "etag", "last-modified", "content-length"}
SIM_THRESHOLD: float = 0.90
PERMUTATIONS: int = 128

# ────────── utilidades ──────────
def load_json_any(path: Union[str, pathlib.Path]) -> List[Dict]:
    path = pathlib.Path(path)
    try:
        with path.open("rb") as f:
            return json.load(f)
    except (json.JSONDecodeError, ValueError):
        data: List[Dict] = []
        with path.open("rb") as f:
            for n, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data.append(json.loads(line))
                except (json.JSONDecodeError, ValueError) as e:
                    print(f"[!] Línea {n} ignorada: {e}", file=sys.stderr)
        return data

def canon_pairs(hdrs: List[Dict], ignore_vals: bool = False):
    if ignore_vals:
        return tuple(
            sorted(
                h["key"].lower()
                for h in hdrs
                if h["key"].lower() not in VOLATILES
            )
        )
    return tuple(
        sorted(
            (h["key"].lower(), h["value"].strip())
            for h in hdrs
            if h["key"].lower() not in VOLATILES
        )
    )

def sha1_short(s: Union[str, bytes]) -> str:
    return hashlib.sha1(s if isinstance(s, bytes) else s.encode()).hexdigest()[:12]

# ────────── carga ──────────
print(f"[*] Cargando '{PATH}'…")
records = load_json_any(PATH)
print(f"    → {len(records)} registros\n")

# ────────── pre-procesado ──────────
rows = []
for site in tqdm(records, desc="Procesando"):
    hdrs = site.get("headers", [])
    keys_only = canon_pairs(hdrs, ignore_vals=True)
    kv_pairs  = canon_pairs(hdrs)

    rows.append({
        "url"         : site.get("final_url") or site.get("url"),
        "key_fp"      : sha1_short(repr(keys_only)),
        "kv_fp"       : sha1_short(repr(kv_pairs)),
        "server"      : next((h["value"] for h in hdrs if h["key"].lower() == "server"), "").lower(),
        "num_headers" : len(hdrs),
        "headers_set" : set(keys_only),
    })

df = pd.DataFrame(rows)

# Mapeamos URL a kv_pairs para usarlos luego en el CSV
url_to_kv_pairs = {
    site.get("final_url") or site.get("url"): canon_pairs(site.get("headers", []))
    for site in records
}

print(df.head(3), "\n")

# ────────── 1) Huellas idénticas de cabeceras ──────────
identical = df.groupby("kv_fp").filter(lambda g: len(g) > 1)
# Añadimos columna con los headers clave-valor
identical["kv_pairs"] = identical["url"].map(url_to_kv_pairs)

identical.to_csv(OUT_DIR / "identical_fingerprints.csv", index=False)
print(f"[+] identical_fingerprints.csv  ({len(identical)})")

# ────────── 2) Near-duplicates usando MinHash ──────────
near_path = OUT_DIR / "near_duplicates.txt"
if MinHash and len(df) > 1:
    lsh = MinHashLSH(threshold=SIM_THRESHOLD, num_perm=PERMUTATIONS)
    minhashes: List[MinHash] = []

    for i, headers in enumerate(df.headers_set):
        m = MinHash(num_perm=PERMUTATIONS)
        for k in headers:
            m.update(k.encode())
        lsh.insert(i, m)
        minhashes.append(m)

    clusters, visited = [], set()
    for i in range(len(df)):
        if i in visited:
            continue
        g = set(lsh.query(minhashes[i]))
        if len(g) > 1:
            clusters.append(g); visited |= g

    with near_path.open("w") as out:
        for g in clusters:
            for idx in g:
                out.write(df.loc[idx, "url"] + "\n")
            out.write("---\n")
    print(f"[+] near_duplicates.txt      ({len(clusters)} grupos)")
else:
    print("[-] MinHash omitido (datasketch no disponible)")

# ────────── 4) Estadísticas de 'Server' ──────────
df.server.value_counts().to_csv(OUT_DIR / "top_server.csv", header=["count"])
print(f"[+] top_server.csv")

print("\n✓ Proceso completado")
