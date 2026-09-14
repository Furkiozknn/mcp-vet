# -*- coding: utf-8 -*-
"""ekosistem-tara.py ciktisini okunur bir ozete cevirir.

Ayirici nokta: bulgular dosya rolune gore ayriliyor. "40 depoda 120 HIGH"
gibi bir cumle, HIGH'larin cogu test dosyasindaysa yaniltici - ve olculdugu
kadariyla cogu oyle. Bu ozet ikisini asla toplamaz.
"""
from __future__ import annotations

import argparse
import io
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mcp_vet.scanning import file_role  # noqa: E402

SIDDET_SIRA = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NOT_FLAGGED"]


def yukle(dizin: Path) -> list[dict]:
    raporlar = []
    for f in sorted(dizin.glob("*.json")):
        if f.name.startswith("_"):
            continue
        d = json.load(io.open(f, encoding="utf-8"))
        d["_depo"] = f.stem.replace("__", "/")
        raporlar.append(d)
    return raporlar


def rolleri_say(rapor: dict) -> tuple[Counter, Counter]:
    """(calisan kodda, disinda) - siddet basina sayim."""
    ic, dis = Counter(), Counter()
    for b in rapor.get("findings") or []:
        yollar = [e.get("path") for e in (b.get("evidence") or []) if e.get("path")]
        calisan = (not yollar) or any(file_role(p) == "shipped" for p in yollar)
        (ic if calisan else dis)[b.get("severity") or "?"] += 1
    return ic, dis


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dizin")
    a = ap.parse_args()
    raporlar = yukle(Path(a.dizin))
    if not raporlar:
        print("rapor bulunamadi", file=sys.stderr)
        return 1

    print(f"{'depo':<38} {'manset':<10} {'calisan kodda':<26} disinda")
    print("-" * 96)
    toplam_ic, toplam_dis = Counter(), Counter()
    for r in sorted(raporlar, key=lambda x: SIDDET_SIRA.index(x.get("overall") or "NOT_FLAGGED")):
        ic, dis = rolleri_say(r)
        toplam_ic.update(ic)
        toplam_dis.update(dis)
        ic_s = " ".join(f"{s[:4]}={ic[s]}" for s in SIDDET_SIRA if ic[s]) or "-"
        dis_s = " ".join(f"{s[:4]}={dis[s]}" for s in SIDDET_SIRA if dis[s]) or "-"
        print(f"{r['_depo']:<38} {str(r.get('overall')):<10} {ic_s:<26} {dis_s}")

    print("-" * 96)
    print(f"{len(raporlar)} depo")
    print("  calisan kodda :", dict(toplam_ic) or "yok")
    print("  disinda       :", dict(toplam_dis) or "yok")
    if toplam_dis:
        oran = sum(toplam_dis.values()) / (sum(toplam_ic.values()) + sum(toplam_dis.values()))
        print(f"\n  Butun bulgularin %{oran * 100:.0f}'i calisan kodun disinda.")
        print("  Bu sayi, rol ayrimi yapmayan bir tarayicinin ne kadar gurultu")
        print("  urettiginin olcusu - ve neden kimsenin ciktisini okumadiginin.")

    print("\n--- calisan kodda CRITICAL/HIGH olanlar ---")
    bulundu = False
    for r in raporlar:
        for b in r.get("findings") or []:
            if b.get("severity") not in ("CRITICAL", "HIGH"):
                continue
            yollar = [e.get("path") for e in (b.get("evidence") or []) if e.get("path")]
            if yollar and not any(file_role(p) == "shipped" for p in yollar):
                continue
            bulundu = True
            print(f"  {r['_depo']}")
            print(f"    [{b['severity']}/{b.get('confidence')}] {b.get('title')}")
            for y in yollar[:2]:
                print(f"      {y}")
    if not bulundu:
        print("  yok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
