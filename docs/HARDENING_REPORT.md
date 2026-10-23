# NightfallLX Hardening Round 2 Hisoboti

**Sana:** 2026-10-23  
**Tarmoq:** `fix/hardening-round-2` (asos: `feat/xss-searchsploit` @ `d69abb5`)  
**Go versiyasi:** `go1.26.5 linux/amd64` (`go.mod` dagi 1.26 direktivasi saqlandi)

## Tuzatishlar holati

1. **Qat'iy belgilangan ishonch darajalari (Confidence)**: `pkg/modules` da `Confidence: 100` o'rniga `SetConfidence` qo'llandi. Himoya sarlavhalari yo'qligi: `possible`, noxavfsiz qiymat/cookie: `probable`. CORS: faqat Origin qaytishi va `ACAC: true` bo'lganda `confirmed`, aks holda `probable`. Host header va Open redirect: faqat Location hosti kanareykaga teng bo'lganda `confirmed`. Testlar qo'shildi. *(Bajarildi — commit `04d89b9`)*.
2. **Hujjatlar aniqligi**: Time-based SQLi uchun kodning asl parametrlari (3s va 6s kechikish) hujjatlashtirildi. Vektorlar soni barcha joyda real `339` deb yozildi. `--dom` birlamchi yoqilganligi va `--dom=false` yoki `--no-dom` orqali o'chirilishi qo'shildi hamda hujjatlashtirildi. *(Bajarildi — commit `af9786d`)*.
3. **Gitignore**: Root `.gitignore` ga `.intel_cache/` va `docs/*_output*` qoidalari mustahkamlandi. *(Bajarildi — commit `f9efd59`)*.
4. **Barcha modullar uchun negativ regressiya testi**: `pkg/modules` da ro'yxatdan o'tgan barcha modullar (upload bundan mustasno) toza statik sahifada tekshirilib, 0 ta zaiflik topishi tasdiqlandi. Statik alert/img sahifasida XSS 0 ta confirmed natija berishi tekshirildi. *(Bajarildi — commit `55d7ff7`)*.
5. **Real searchsploit testi**: `NFLX_REAL_SEARCHSPLOIT=1` muhit o'zgaruvchisi o'rnatilganda va searchsploit mavjud bo'lganda `Lookup("php", "3.4.5")` chaqiruvini bajaruvchi test qo'shildi (171 ta topilma muvaffaqiyatli parse qilindi, birlamchi holatda skip qilinadi). *(Bajarildi — commit `a707b56`)*.

## Test natijalari

- **Oldin:** `go vet ./...` (0 ogohlantirish), `go test -count=1 ./...` (barcha paketlar PASS).
- **Keyin:** `go vet ./...` (0 ogohlantirish), `go test -count=1 ./...` (PASS), `go test -count=1 -race ./...` (0 data race, barchasi PASS).
- **O'zgargan testlar:** `pkg/modules` da 23 ta asosiy va 23 ta subtest (jami 46 ta, barchasi PASS); `pkg/intel` da 6 ta test (barchasi PASS/SKIP).
- **Bajarilmagan ishlar:** Yo'q, barcha talablar 100% to'liq bajarildi.
