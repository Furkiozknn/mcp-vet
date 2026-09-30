# Tasarım: mcp-vet ilk kullanım ve README yenilemesi (30 Eylül 2026)

## Hedef

Videodan ya da profilden gelen biri ilk dakikada şunu yapabilmeli: aracın ne yaptığını tek cümlede anlamak, tek komutla kurmak, gerçek bir MCP sunucusunda ilk sonucu almak; ilk komutu yanlış yazarsa doğrusunu ekranda görmek. Çekirdek davranış (kurallar, risk modeli, çıkış kodları, JSON sözleşmesi, hiçbir şeyi çalıştırmama garantisi) değişmedi; sürüm numarası artmadı (0.6.0).

## Önce / sonra

| Konu | Önce | Sonra |
|---|---|---|
| README ilk ekranı | banner, 15 sn'lik sesli reel, altı rozet, elle kısaltılmış bir SVG, "What is this" listesi; kurulum en altta, ilk komut yer tutucu | banner, tek cümlelik tanım, üç satırlık kurulum + ilk denetim (`pipx`/`uvx`), 18 sn gerçek çıktılı terminal demosu, ölçülmüş süre, "ne zaman kullanılır / kullanılmaz" tablosu, sonra rozetler ve eski gövde |
| Demo | kaynağı depoda olmayan reel/GIF/SVG | `scripts/demo-uret.py`: 5 komut gerçekten koşulur, `docs/demo/komutlar.txt` kayıttır, sayfa o kaydı yazma animasyonuyla oynatır; `demo-kayit.js` mp4/gif alır |
| İlk yanlış komut (`audit ./checkout`) | GitHub'a `repos/./checkout` sorulur, "not found - not found" | istek atılmaz, `hint: mcp-vet audit --offline --path ./checkout` |
| `--help` | açıklama + çıkış kodları | çalışan bir başlangıç (klonla, denetle), her komut için bir örnek, çıkış kodları, "nothing above INFO safe değildir" |
| Eksik/yanlış argüman | tek satır | aynı satır + yazılacak komut; dosya mı yok mu ayrımı; kullanım hatası `--help`'e yönlendirir |
| 404 / ağ yok | tekrarlı mesaj, çıkış yolu yok | tek mesaj + "özel depo da 404 döner" / "ağ yoksa `--offline`" |
| Okunamayan dosya | "ikili dosya" sayılıp NOT_FLAGGED | `notes.skipped_unreadable` + "could not be read ... a clean result does not cover them" |
| Örnek rapor / diff örneği | kesik / elle özet | tam çıktı / gerçek çıktı |
| SKILL.md | göreli yol ve çıkış kodu 4 anlatılmamış | "Running the tool" bölümü |
| Test | 482 | 552 (+70: ilk kullanım mesajları 43, README/SKILL komutları 18, okunamayan dosya 5, kaynak-hijyen testinin yeni dosyalara açılan 4 satırı) |

## CLI akışı

```
kur                  pipx install git+https://github.com/Furkiozknn/mcp-vet
                     (ya da hiç kurmadan: uvx --from git+... mcp-vet ...)
klonla               git clone --depth 1 <sunucu> ./checkout        mcp-vet klonlamaz
denetle              mcp-vet audit --offline --path ./checkout       çıkış 0/1/2/3, 4 = bakamadı
ayrıntı              --verbose | --json | mcp-vet report ...
güncelleme           mcp-vet diff --before-path ./v1 --after-path ./v2   (ya da owner/repo ref ref)
yanlış komut         error: ... + hint: doğru komut, çıkış 4
```

Kurulum ve ilk sonuç süresi ölçüldü (`DENETIM.md`): boş önbellekle `uvx` 12,7-19,1 s, `pipx` 18 s, denetim 1,4-1,7 s.

## Görsel dil (video sisteminden alınanlar)

README görselleri ve demo FRK-OS kimliğinde; ürünün kendi kimliği (güvenlik denetçisi) bu dilden çelişmediği için ortak palet olduğu gibi kullanıldı.

| Ne | Nereden | Nerede |
|---|---|---|
| `zemin #0e0d0b`, panel `#14120e`, `yazi #f1ece2`, ilk vurgu `#ffc21a` | `sosyal/uret/tema.mjs` `klasik.akis` | terminal sahnesi zemini, panel, metin, sarı `$` isteği/sol çizgi/`hint:` |
| vurgu renkleri `#ff4d6d` (mercan), `#ff7a1a` (turuncu), `#19d3e6` (camgöbeği) | `tema.mjs` klasik vurgular | önem derecesi kelimeleri: HIGH/CRITICAL mercan, MEDIUM/LOW turuncu, NOT_FLAGGED camgöbeği, `error:` mercan. Yalnızca boyama; metin değişmez |
| `doku: "izgara"` | `tema.mjs` klasik | gövdede çok soluk sabit ızgara (`rgba(241,236,226,.045)`, 48 px) |
| JetBrains Mono (mono etiket) | `tema.mjs` `F.jb` | tüm terminal metni; SIL OFL 1.1, `assets/yazi/`, tam kümeden (kutu çizgisi `─` latin altkümede yok) |
| `terminal: "koyu"` sahnesi, 30 ms/harf yazma, satır satır çıktı | `tema.mjs` `tercih.terminal`, `sahne.js` terminal tekniği | `scripts/demo-uret.py` sayfası |

Bilerek alınmayanlar: League Gothic başlık (README'nin görsel başlığı yok; banner profil üreticisinden), geçişler (iris, glitch, flaş...): bir denetim aracının demosunda çıktının kendisi okunmalı, geçiş dikkat dağıtır. Terminal sayfası `prefers-reduced-motion`'da imleç yanıp sönmesini kapatır.

Kontrast (panel `#14120e` üstünde, WCAG göreli parlaklıktan hesaplandı): krem 15,9:1, sönük metin `#b6ae9d` 8,5:1, sarı 11,6:1, mercan 5,8:1, turuncu 7,2:1, camgöbeği 10,3:1; hepsi ≥ 4,5:1. Panelin sayfa zeminine oranı 1,04:1 (sınır çizgisi ve sol sarı çizgi ayırıyor).

## Kararlar ve sınırlar

- **Banner değişmedi.** `assets/banner.svg` hesabın banner üreticisinden geliyor (GitHub mavisi, FRK-OS değil); bu depoda elle değiştirmek üreticinin bir sonraki çıktısında silinir. FRK-OS bannera geçmek profil deposundaki üretici/`banners.json` işidir.
- **Reel, `audit.gif`, `audit.svg` çıkarıldı**: üreticileri depoda yoktu, yeniden üretilemedi (`DENETIM.md`). Git geçmişinde duruyorlar.
- Demo gerçek bir üçüncü taraf değil, hesabın kendi sunucusunu (`nvidia-nim-mcp`, `da9618a`) denetler; denetlenen SHA `komutlar.txt` başında yazılı. `mcp-vet` demoda PATH'ten gelir (`pip install .` ile kurulmuş dal sürümü); kurulum süresi ayrıca `kurulum.txt`'te ölçülür, demonun içinde koşturulmaz.
- Yanlış-komut sahnesi (`audit ./checkout`) demoda bilerek son sırada: aracın ilk kullanıcıya davranışı da ürünün parçası.
- Demo dikey 1080x1920 kaydı (`demo-dikey.mp4`) depoya girmedi; günlük video hattı için `sosyal/medya/projeler/mcp-vet/terminal.mp4` altında.
- CI: `cli-contract` işine "klasör owner/repo yerine yazılırsa çıkış 4 ve doğru komut yazılı" adımı eklendi. Sürüm, etiket, PyPI, dizin/awesome-list başvurusu ve Pages **yapılmadı** (onay kapısı).
