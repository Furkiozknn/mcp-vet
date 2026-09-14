# -*- coding: utf-8 -*-
"""Bir MCP sunucusu listesini sigla klonlayip mcp-vet ile denetler.

Neden var: `mcp-vet audit <owner>/<repo>` uzaktan yalnizca ustveriye bakar -
kaynak analizi icin calisma kopyasi gerekiyor, ve bu dogru davranis. Bu betik
o adimi otomatiklestirir: klonla, denetle, JSON'u sakla, klonu sil.

Kasitli sinirlar:
  - `--depth 1`: gecmis gerekmiyor, bant genisligi ve disk bosa gitmesin.
  - Klon her denetimden sonra siliniyor; 20 depo diskte birikmesin.
  - `--offline`: denetim sirasinda ag yok. Denetlenen kodun ag cagrisi
    yapmasi zaten imkansiz (mcp-vet hicbir seyi calistirmaz) ama denetimin
    kendisi de disariya bagli olmamali ki sonuc tekrarlanabilsin.

Kullanim:
    python scripts/ekosistem-tara.py depolar.txt --cikti sonuc/
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

KOK = Path(__file__).resolve().parent.parent
MCP_VET = KOK / ".venv" / "Scripts" / "mcp-vet.exe"
if not MCP_VET.exists():
    MCP_VET = KOK / ".venv" / "bin" / "mcp-vet"


def kabuk(args: list[str], zaman_asimi: int = 300) -> tuple[int, str]:
    try:
        p = subprocess.run(
            args, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=zaman_asimi,
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "zaman asimi"
    except Exception as e:  # klon/denetim bir depoda patlarsa tarama durmasin
        return 1, str(e)


def bir_depo(slug: str, cikti: Path) -> dict:
    """Tek bir depoyu klonlayip denetler. Sonuc her durumda sozluk doner."""
    sonuc: dict = {"repo": slug}
    gecici = Path(tempfile.mkdtemp(prefix="mcpvet-"))
    try:
        kod, log = kabuk(
            ["git", "clone", "--depth", "1", "--quiet",
             f"https://github.com/{slug}.git", str(gecici / "kopya")],
            zaman_asimi=240,
        )
        if kod != 0:
            sonuc["hata"] = f"klonlanamadi: {log.strip()[:120]}"
            return sonuc

        hedef = cikti / (slug.replace("/", "__") + ".json")
        kod, log = kabuk(
            [str(MCP_VET), "report", "--offline", "--path", str(gecici / "kopya")],
            zaman_asimi=300,
        )
        # `report` bulgu siddetine gore SIFIR OLMAYAN cikis kodu verir; bu
        # tasarim geregi, hata degil. Cikis kodunu degil ciktiyi okuyoruz.
        ham = log.strip()
        basla = ham.find("{")
        if basla < 0:
            sonuc["hata"] = f"JSON uretilmedi (cikis {kod}): {ham[:120]}"
            return sonuc
        try:
            rapor = json.loads(ham[basla:])
        except json.JSONDecodeError as e:
            sonuc["hata"] = f"JSON ayristirilamadi: {e}"
            return sonuc

        hedef.write_text(json.dumps(rapor, indent=1, ensure_ascii=False), encoding="utf-8")
        bulgular = rapor.get("findings") or []
        sonuc.update(
            cikis=kod,
            risk=rapor.get("overall") or rapor.get("overall_risk"),
            bulgu=len(bulgular),
            siddetler=sorted({(f.get("severity") or "?") for f in bulgular}),
            dosya=hedef.name,
        )
        return sonuc
    finally:
        shutil.rmtree(gecici, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("liste", help="her satirda bir owner/repo")
    ap.add_argument("--cikti", default="tarama", help="JSON raporlarin yazilacagi dizin")
    a = ap.parse_args()

    if not MCP_VET.exists():
        print(f"mcp-vet bulunamadi: {MCP_VET}", file=sys.stderr)
        return 2

    cikti = Path(a.cikti)
    cikti.mkdir(parents=True, exist_ok=True)

    slugler = [
        s.strip() for s in Path(a.liste).read_text(encoding="utf-8").splitlines()
        if s.strip() and not s.strip().startswith("#")
    ]
    print(f"{len(slugler)} depo taranacak\n")

    hepsi = []
    for i, slug in enumerate(slugler, 1):
        print(f"[{i}/{len(slugler)}] {slug} ... ", end="", flush=True)
        r = bir_depo(slug, cikti)
        hepsi.append(r)
        if "hata" in r:
            print(f"ATLANDI ({r['hata'][:60]})")
        else:
            print(f"{r['risk']}  bulgu={r['bulgu']}  {','.join(r['siddetler'])}")

    (cikti / "_ozet.json").write_text(
        json.dumps(hepsi, indent=1, ensure_ascii=False), encoding="utf-8"
    )
    basarili = [r for r in hepsi if "hata" not in r]
    print(f"\n{len(basarili)}/{len(hepsi)} denetlendi -> {cikti}/_ozet.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
