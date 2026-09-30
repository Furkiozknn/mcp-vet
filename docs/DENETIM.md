# Denetim: mcp-vet (30 Eylül 2026)

Yenilemeden önce `master` (0.6.0, `223cad6`) üzerinde, bu makinede (Windows 11, Python 3.12 venv ve uv'nin 3.14'ü, uv 0.12.5, Git Bash) ölçüldü. Ölçülmeyen bir şey yazılmadı. Ham çıktılar ve ekran görüntüleri depo dışında: `kanit/mcp-vet/{once,sonra}/` (aynı 13 komut, iki sürüme karşı: `olc.py`).

## Temiz ortamda kurulum ve ilk sonuç

Her satır boş bir klasörde, boş bir önbellekle koşuldu.

| Yol | Süre | Sonuç |
|---|---|---|
| `uvx --from git+https://github.com/Furkiozknn/mcp-vet mcp-vet --version` (boş uv önbelleği) | 19,1 s, 12,7 s ve 12,8 s (üç ayrı koşu; GitHub'dan çekip derliyor) | `mcp-vet 0.6.0` |
| aynısı, önbellek sıcak | 3,3 s ve 2,4 s | aynı |
| `pipx install git+https://github.com/Furkiozknn/mcp-vet` (`uvx pipx`, yalıtılmış `PIPX_HOME`; pipx makinede kurulu değil) | 18,1 s | `mcp-vet 0.6.0` |
| `python -m venv` + `pip install git+https://...` | 9,8 s + 15,6 s | `mcp-vet 0.6.0` |
| `git clone --depth 1` (nvidia-nim-mcp) | 1,5 s | |
| `mcp-vet audit --offline --path ./checkout` | 1,4-1,7 s | verdict + rapor |

"Tek komutla kur, bir dakikada ilk sonuç" tutuyor: kurulum + klon + denetim, en kötü ölçümle 19 + 1,5 + 1,7 = ~22 s. Kurulum süresi GitHub'a ve önbelleğe bağlı; iki koşu arasındaki fark (19 s / 13 s) bunu gösteriyor.

## README komutları

| Komut | Sonuç |
|---|---|
| `git clone --depth 1 https://github.com/<owner>/<server> ./checkout` | yer tutucu; kopyalanınca çalışmaz. Gerçek bir sunucuyla (`Furkiozknn/nvidia-nim-mcp`) çalıştı |
| `uvx --from git+... mcp-vet audit --offline --path ./checkout` | çalıştı, çıkış 1 (LOW/MEDIUM), README'nin söylediği gibi |
| `mcp-vet search "discord mcp" --limit 3` | çalıştı. Tablo yalnız yıldız/çatal/yaş sıralıyor; ilk üç sonuç Scrapling, AstrBot, Klavis (discord'la ilgisiz). README bunu zaten söylüyor ("ranks one gameable signal"); açıklama sütunu yok, değiştirilmedi |
| `mcp-vet registry discord --limit 3` | çalıştı; `registry "control discord"` (çok kelimeli) de sonuç verdi, README'nin "tek kelime kullan" uyarısı katı değil |
| `mcp-vet check Furkiozknn/mcp-vet` | çalıştı |
| `mcp-vet diff owner/repo v1.2.0 v1.3.0` | yer tutucu. Hesaptaki hiçbir depoda etiket yok; gerçek çalıştırma commit SHA'larıyla (`98b4c66 da9618a`, 7,7 s, çıkış 1: `+ package.install`). Yerel biçim `--before-path/--after-path` çalıştı (çıkış 2) |
| `mcp-vet audit owner/repo --path ./checkout --no-cache`, `--verbose`, `--quiet`, `--json` | çalıştı |
| `mcp-vet report ... > report.json` | geçerli JSON, iki koşuda bayt bayt aynı (`cmp`), `jq '.findings[] | select(...)'` çalıştı |
| `python3 scripts/vet.py ...`, `uv run python scripts/vet.py ...` | çalıştı; Windows'ta `python3` yok, `uv run` yolu geçerli |
| Skill kurulumu (SKILL.md + scripts/vet.py + mcp_vet kopyala) | geçici klasörde `python scripts/vet.py --version` → 0.6.0 |
| CI YAML parçası (`set +e`, çıkış 4 → hata, `>=2` → hata) | mantık `tests/` ve CI `cli-contract` işinde zaten sınanıyor |
| `pip install -e .[dev]` + `pytest` | 482 geçti, 11,5 s |

Sayılar: "482 tests" → koşudan 482 (uyuştu). "32 rules" → `patterns.ALL_RULES` 32 (uyuştu). Yanıt önbelleği tablosu → **bayat** (aşağıda).

## Hata mesajları ve `--help`

Çıkış kodları hep doğruydu (kullanım hatası, olmayan yol, boş klasör, ağ yok → 4). Sorun sözlerdeydi:

| Girdi | Önce | Sorun |
|---|---|---|
| `mcp-vet audit ./checkout` | `error: not found - not found: https://api.github.com/repos/./checkout` | **Hata.** `.` ve `..` owner/repo desenine uyuyor; klasör GitHub'a depo diye soruluyordu (bir istek, jeton dahil). İlk denemede en olası yanlış |
| `mcp-vet check Furkiozknn/yok` | `error: not found - not found: <url>` | "not found" iki kez; özel depo da 404 döndüğü söylenmiyor |
| ağ yok | `error: could not reach <url> ([WinError ...])` | çıkış yolu (`--offline`) söylenmiyor |
| `audit --offline` (yolsuz), `audit` (hedefsiz) | tek satır | doğru komut yazılı değil |
| `--path dosya.md` / `--path yok` | `is not a directory` | dosya mı yok mu ayırt edilmiyor |
| `--help` | açıklama + çıkış kodları | örnek yok; alt komutların örneği yok; `report --path/--offline/--no-registry/--purpose` yardım metni yok |
| kullanım hatası | usage + hata | `--help`'e yönlendirme yok |
| okunamayan dosya (izin yok) | **`1 binary file(s) were not analyzed`**, NOT_FLAGGED, çıkış 0 | **Hata.** Windows'ta `icacls /deny` ile bir kaynak dosyanın okuması kapatıldı: rapor onu "ikili" saydı (yanlış sebep). Boyutu bile alınamayan dosya hiç raporlanmıyordu |

Önce/sonra metinleri ve ekran görüntüleri: `kanit/mcp-vet/once/`, `sonra/` (`komutlar.txt`, `ilk-yanlis-komut.png`, `eksik-arguman.png`, `yardim.png`).

## README bulguları

- **Yanıt önbelleği tablosu bayat.** "Her koşu bir saat içinde 0,23 s" yazıyordu; bugün aynı komut (`audit Furkiozknn/mcp-vet --path .`) ilk koşuda 9,0 s, önbellekten 3,5 s (0 istek), `--offline` 4,0 s. Depo büyüdü, kaynak taraması artık ~3,5-4 s. "Kayıt altındaki yük altında 55,2 s" bugün yeniden üretilemedi. Tablo 30 Eylül sütunuyla güncellendi, 4 Eylül sütunu olduğu gibi bırakıldı.
- Örnek rapor `exfil_server` çıktısının **kesilmiş** hâliydi ("What this did not check" bölümü yoktu) ama "Real output" deniyordu. Tam çıktı kondu.
- Sürüm farkı örneği (`v1.2.0 -> v1.3.0`, "can do something v1.2.0 could not...") elle yazılmış bir özetti. Yerine gerçek `diff --before-path/--after-path` çıktısı kondu.
- `assets/audit.svg`: "A real run, abridged", ama elle kısaltılmış bir SVG (üç bulgu; gerçek koşu daha fazla veriyor) ve üretici depoda yok. `assets/audit.gif` ve `docs/reel/reel.{gif,mp4}` ("15 saniyelik, sesli reel") için de üretici yok. **Yeniden üretilemediği için README'den ve depodan çıkarıldı** (git geçmişinde duruyor). Yerine `scripts/demo-uret.py` ile gerçek çıktıdan üretilen demo geldi.
- İlk ekran: banner + reel + 6 rozet + SVG + "What is this" uzun listesi; kurulum komutu ilk ekranda yoktu (ilk komut `<owner>/<server>` yer tutuculuydu ve `uvx`'in yalnız audit satırı vardı, kurulum "Install" bölümündeydi).
- `assets/banner.svg` profil deposundaki üreticiden geliyor ("edit banners.json there, not this file"), GitHub mavisi paleti (`#0d1117`/`#58a6ff`) kullanıyor, FRK-OS değil. Bu depoda elle değiştirilmedi; hesap genelindeki banner sistemine ait bir karar.

## SKILL.md

Komutlar CLI ile tutarlı (arama → köken → güven → sunma → denetim → sentez → onay). Bulgu: `uv run python scripts/vet.py` yolu skill klasörüne görelidir; Claude proje klasöründen çalıştırırsa bulamaz, hiçbir yerde söylenmiyordu. "Exit code 4 temiz sonuç değildir" da skill'de yazmıyordu. İkisi "Running the tool" bölümüyle eklendi.

## Testler ve CI

Önce: 482 test, hepsi geçti, 11,5 s (Python 3.14 ve `uv run --extra dev`). CI: `ci.yml` (4 sürüm matrisi 3.9-3.13, `cli-contract`, `paket`) ve `yayinla.yml`; `master`'daki son CI ve CodeQL koşuları yeşil (`223cad6`); 28 Eylül'deki bir "Dependabot Updates" işi kırmızı (CI değil, bu görevin kapsamı dışı, dokunulmadı). Sonra: bkz. `TASARIM.md` sonu ve PR.

## Günlük "Ekosistem denetimi" (#19, profil deposu)

Bu depoya ait açık bulgular yalnızca profil deposundaki meta-source ayrışmasının parçaları: `project-meta.json` testleri (482) ↔ `meta-source.json` (319) ve `summary` ↔ depo `description` ("31 rules ... 289 tests", GitHub'da hâlâ eski). Furki'nin kararı beklendiği için (`/meta` birleşmiş içeriği geri alır) **kapatılmadı**; bu dalda `project-meta.json`'a yalnızca gerçekten değişen alanlar (medya yolu, test sayısı) işlendi.

## Çözülmeyenler

- `mcp-vet search` sonuçları yıldıza göre sıralanıyor ve açıklama göstermiyor; ürün kararı (yıldız güven değildir) olduğu için değiştirilmedi.
- Etiket yok: `diff owner/repo v1 v2` örneği README'de yer tutucu olarak kaldı; komut SHA ile çalışıyor.
- `pipx` bu makinede kurulu değil; `uvx pipx` ile yalıtılmış olarak denendi.
- GitHub depo `description`'ı ve `meta-source.json` bayat (yukarıda).
