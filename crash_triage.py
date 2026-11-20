"""Prototipo extendido: triaje, cobertura y resumen de campana de fuzzing.

No ejecuta Unicorn ni ningun binario: trabaja sobre REGISTROS de ejecucion.
Incluye huellas de crash, deduplicacion, minimizacion delta-debugging,
metricas de cobertura de aristas, tasa de reproduccion e informe de campana.
Todos los datos incluidos son SINTETICOS.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def fingerprint(crash: dict) -> str:
    """Huella estable: senal + RIP + stack (ignora timestamps y rutas)."""
    raw = f"{crash.get('signal')}|{crash.get('rip')}|{crash.get('stack')}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def dedupe(crashes: list[dict]) -> dict:
    groups: dict[str, dict] = {}
    for crash in crashes:
        fp = fingerprint(crash)
        if fp not in groups:
            groups[fp] = {"fingerprint": fp, "count": 0, "example": crash}
        groups[fp]["count"] += 1
    return {
        "total": len(crashes),
        "unique": len(groups),
        "groups": sorted(groups.values(), key=lambda g: -g["count"]),
    }


def minimize(seed: bytes, triggers, max_rounds: int = 100) -> bytes:
    """Reduce bytes conservando `triggers` (delta-debugging simplificado)."""
    data = seed
    n = 2
    for _ in range(max_rounds):
        if len(data) <= 1:
            break
        chunk = max(1, len(data) // n)
        changed = False
        for start in range(0, len(data), chunk):
            candidate = data[:start] + data[start + chunk :]
            if triggers(candidate):
                data = candidate
                changed = True
                n = max(2, n - 1)
                break
        if not changed:
            if n >= len(data):
                break
            n = min(len(data), n * 2)
    return data


def coverage_summary(records: list[dict]) -> dict:
    """Cobertura acumulada de aristas a partir de registros con campo `edges`."""
    seen: set[str] = set()
    per_run: list[dict] = []
    for record in records:
        edges = set(record.get("edges", []))
        new = sorted(edges - seen)
        seen |= edges
        per_run.append({"run": record.get("run", len(per_run)), "edges": len(edges), "new_edges": len(new)})
    return {
        "runs": len(records),
        "total_edges": len(seen),
        "edges": sorted(seen),
        "per_run": per_run,
    }


def reproducibility(crashes: list[dict]) -> dict:
    """Tasa de crashes que se reprodujeron al menos una vez."""
    if not crashes:
        return {"total": 0, "reproduced": 0, "rate": None}
    reproduced = sum(1 for c in crashes if c.get("reproduced"))
    return {"total": len(crashes), "reproduced": reproduced, "rate": round(reproduced / len(crashes), 4)}


def campaign_summary(crashes: list[dict]) -> dict:
    """Informe combinado de una campana sintetica."""
    d = dedupe(crashes)
    return {
        "crashes": d,
        "coverage": coverage_summary(crashes),
        "reproducibility": reproducibility(crashes),
        "exec_per_unique_crash": round(d["total"] / d["unique"], 4) if d["unique"] else None,
    }


def load_json(path: str | Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_dedupe = sub.add_parser("dedupe")
    p_dedupe.add_argument("crashes")

    p_report = sub.add_parser("report")
    p_report.add_argument("crashes")

    p_min = sub.add_parser("minimize")
    p_min.add_argument("--seed", default="xxxCRASHyyy")
    p_min.add_argument("--marker", default="CRASH")

    args = parser.parse_args()
    if args.command == "minimize":
        result = minimize(args.seed.encode(), lambda b: args.marker.encode() in b)
        print(result.decode(errors="replace"))
    else:
        crashes = load_json(args.crashes)
        payload = dedupe(crashes) if args.command == "dedupe" else campaign_summary(crashes)
        print(json.dumps(payload, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
