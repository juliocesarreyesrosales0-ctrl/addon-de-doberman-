#!/usr/bin/env python3
"""Genera app/src/main/assets/threat_db.json a partir de fuentes públicas de indicadores.

Fuentes (formato STIX2):
  * Stalkerware Indicators de Echap (CC BY 4.0)
    https://github.com/AssoEchap/stalkerware-indicators
  * Índice de indicadores de MVT (Mobile Verification Toolkit, Amnesty Tech y otros)
    https://github.com/mvt-project/mvt-indicators

Solo usa la biblioteca estándar de Python. Si PyYAML está instalado se lee el índice de MVT
completo; si no, se usa una lista fija de archivos conocidos.

Uso:
    python3 tools/build_threat_db.py            # descarga y escribe el asset
    python3 tools/build_threat_db.py --check    # solo muestra estadísticas
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "app" / "src" / "main" / "assets" / "threat_db.json"

ECHAP_STIX = ("https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/"
              "master/generated/stalkerware.stix2")
MVT_INDEX = "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml"
# Respaldo si no hay PyYAML: archivos de MVT con indicadores útiles para Android.
MVT_FALLBACK = [
    ("RCS Lab", "mvt-project/mvt-indicators/main/2022-06-23_rcs_lab/rcs.stix2"),
    ("WyrmSpy y DragonEgg", "mvt-project/mvt-indicators/main/2023-07-25_wyrmspy_dragonegg/wyrmspy_dragonegg.stix2"),
    ("NoviSpy", "mvt-project/mvt-indicators/main/2024-12-16_serbia_novispy/novispy.stix2"),
    ("EagleMsgSpy", "mvt-project/mvt-indicators/main/2024-12-25_eaglemsgspy/eaglemsgspy.stix2"),
    ("ResidentBat", "mvt-project/mvt-indicators/main/ResidentBat/residentbat.stix2"),
    ("Cellebrite", "mvt-project/mvt-indicators/main/cellebrite/cellebrite.stix2"),
]

SEVERITY_ORDER = {"spyware": 3, "stalkerware": 2, "watchware": 1}
PATTERN_RE = re.compile(r"^\[([a-z0-9:._-]+)\s*=\s*'(.*)'\]$")


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "doberman-threat-db-builder"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def mvt_sources() -> list[tuple[str, str]]:
    """Devuelve [(nombre, url_raw)] de los archivos STIX2 listados por MVT."""
    try:
        import yaml  # type: ignore
    except ImportError:
        return [(n, "https://raw.githubusercontent.com/" + p) for n, p in MVT_FALLBACK]
    data = yaml.safe_load(fetch(MVT_INDEX))
    out = []
    for e in data.get("indicators", []):
        g = e.get("github") or {}
        if g:
            url = f"https://raw.githubusercontent.com/{g['owner']}/{g['repo']}/{g['branch']}/{g['path']}"
        else:
            url = e.get("download_url")
        if url and "stalkerware" not in url:  # stalkerware se descarga directo de Echap
            out.append((e.get("name", url), url))
    return out


def parse_stix(raw: bytes, default_type: str):
    """Extrae (familia, tipo) -> indicadores de un bundle STIX2."""
    bundle = json.loads(raw)
    malware, indicators, rels = {}, {}, []
    for o in bundle.get("objects", []):
        t = o.get("type")
        if t == "malware":
            desc = (o.get("description") or "").lower()
            if "watchware" in desc:
                kind = "watchware"
            elif "stalkerware" in desc:
                kind = "stalkerware"
            else:
                kind = default_type
            malware[o["id"]] = (o.get("name") or "Desconocido", kind)
        elif t == "indicator":
            m = PATTERN_RE.match(o.get("pattern", "").strip())
            if m:
                indicators[o["id"]] = (m.group(1), m.group(2))
        elif t == "relationship":
            rels.append((o.get("source_ref"), o.get("target_ref")))
    result = []
    for src, dst in rels:
        if src in indicators and dst in malware:
            result.append((malware[dst], indicators[src]))
    # Si sólo hay una familia y faltan relaciones, asociar todo a ella.
    if not result and len(malware) == 1:
        only = next(iter(malware.values()))
        result = [(only, ind) for ind in indicators.values()]
    return result


def build() -> dict:
    families: list[list[str]] = []
    fam_index: dict[tuple[str, str], int] = {}
    packages: dict[str, int] = {}
    certs: dict[str, int] = {}
    hashes: dict[str, int] = {}

    def fam(name: str, kind: str, source: str) -> int:
        key = (name, kind)
        if key not in fam_index:
            fam_index[key] = len(families)
            families.append([name, kind, source])
        return fam_index[key]

    def put(table: dict[str, int], key: str, idx: int):
        prev = table.get(key)
        if prev is None or SEVERITY_ORDER[families[idx][1]] > SEVERITY_ORDER[families[prev][1]]:
            table[key] = idx

    sources = [("echap", "Stalkerware Indicators (Echap)", ECHAP_STIX, "stalkerware")]
    sources += [("mvt", name, url, "spyware") for name, url in mvt_sources()]

    used_sources = set()
    for source_id, name, url, default_type in sources:
        try:
            pairs = parse_stix(fetch(url), default_type)
        except Exception as ex:  # una fuente caída no debe romper todo
            print(f"  ! {name}: {ex}", file=sys.stderr)
            continue
        n_before = len(packages) + len(certs) + len(hashes)
        for (fname, kind), (field, value) in pairs:
            if field == "app:id":
                put(packages, value.strip(), fam(fname, kind, source_id))
            elif field == "app:cert.sha1":
                put(certs, value.strip().upper().replace(":", ""), fam(fname, kind, source_id))
            elif field == "file:hashes.sha256":
                v = value.strip().lower()
                if re.fullmatch(r"[0-9a-f]{64}", v):
                    put(hashes, v, fam(fname, kind, source_id))
        added = len(packages) + len(certs) + len(hashes) - n_before
        if added:
            used_sources.add(source_id)
        print(f"  + {name}: {added} indicadores nuevos")

    now = dt.datetime.now(dt.timezone.utc)
    return {
        "format": 1,
        "version": now.strftime("%Y.%m.%d"),
        "generated": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": [s for s in [
            {"id": "echap", "name": "Stalkerware Indicators – Echap",
             "url": "https://github.com/AssoEchap/stalkerware-indicators", "license": "CC BY 4.0"},
            {"id": "mvt", "name": "MVT indicators (Amnesty Tech y colaboradores)",
             "url": "https://github.com/mvt-project/mvt-indicators", "license": "MIT"},
        ] if s["id"] in used_sources],
        "families": families,
        "packages": dict(sorted(packages.items())),
        "certs": dict(sorted(certs.items())),
        "sha256": dict(sorted(hashes.items())),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="no escribir el archivo")
    args = ap.parse_args()
    db = build()
    print(f"Familias: {len(db['families'])}  Paquetes: {len(db['packages'])}  "
          f"Certificados: {len(db['certs'])}  SHA-256: {len(db['sha256'])}")
    if len(db["packages"]) < 100:
        print("Base demasiado pequeña; ¿falló la descarga?", file=sys.stderr)
        return 1
    if not args.check:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(db, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
        print(f"Escrito {OUT.relative_to(ROOT)} ({OUT.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
