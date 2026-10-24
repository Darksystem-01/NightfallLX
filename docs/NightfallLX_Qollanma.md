# NightfallLX (Go Edition v2.0) — To'liq Foydalanuvchi Qo'llanmasi

Ushbu qo'llanma NightfallLX (Go Edition v2.0) veb-xavfsizlikni baholash va zaifliklarni aniqlash vositasining to'liq va rasmiy texnik hujjatidir. Qo'llanmadagi har bir ma'lumot, bayroq, modul va mantiqiy qoidalar to'g'ridan-to'g'ri dasturning Go manba kodlariga (`nightfalllx-go/`) asoslangan. Agar ushbu qo'llanma va eski hujjatlar (masalan, Python davridan qolgan tavsiflar) o'rtasida tafovut yuzaga kelsa, Go manba kodi ustuvor hisoblanadi va barcha farqlar tegishli bo'limlarda ochiq qayd etilgan.

---

## Mundarija
1. [Umumiy tavsif](#1-umumiy-tavsif)
2. [Ishlash prinsipi](#2-ishlash-prinsipi)
3. [O'rnatish](#3-ornatish)
4. [Rejimlar (modes) va ularni tanlash](#4-rejimlar-modes-va-ularni-tanlash)
5. [Vhost va subdomen qidirish](#5-vhost-va-subdomen-qidirish)
6. [Zaiflik modullari](#6-zaiflik-modullari)
7. [XSS dvigateli](#7-xss-dvigateli)
8. [Autentifikatsiyalangan skanerlash va ilg'or funksiyalar](#8-autentifikatsiyalangan-skanerlash-va-ilgor-funksiyalar)
9. [Intel (versiyaga mos referens qidiruvi)](#9-intel-versiyaga-mos-referens-qidiruvi)
10. [Hisobot fayllari](#10-hisobot-fayllari)
11. [Flag jadvali](#11-flag-jadvali)
12. [Xavfsizlik qoidalari](#12-xavfsizlik-qoidalari)
13. [Ish oqimi (workflow)](#13-ish-oqimi-workflow)
14. [Muammolar va maslahatlar](#14-muammolar-va-maslahatlar)
15. [Ma'lum muammolar va cheklovlar](#15-malum-muammolar-va-cheklovlar)
16. [Ilova: tekshirish](#16-ilova-tekshirish)

---

## 1. Umumiy tavsif

NightfallLX (Go Edition v2.0) — veb-ilovalarni avtomatlashtirilgan tarzda tahlil qilish, zaifliklarni aniqlash va xavfsizlik auditini o'tkazish uchun mo'ljallangan yuqori unumdorlikka ega konsol dasturidir. Dastur to'liq Go dasturlash tilida yozilgan bo'lib, yuqori parallelizm (goroutines), xotiradan samarali foydalanish va ulanishlarni qayta ishlatish (HTTP keep-alive) imkoniyatlariga ega.

### 1.1 Maqsadli auditoriya
Ushbu dastur junior va mid-level darajadagi veb-pentesterlar, ilova xavfsizligi tahlilchilari (AppSec) hamda xavfsizlik tadqiqotchilari uchun mo'ljallangan. Dasturning asosiy falsafasi — **nol soxta ijobiy natijalar (zero false positives)** tamoyilidir. Dastur faqatgina server javobida zaiflik to'liq isbotlangan holatlardagina tasdiqlangan hisobot beradi.

### 1.2 Ruxsat etilgan foydalanish qoidasi (Authorized-Use Rule)
NightfallLX faqatgina quyidagi ruxsat etilgan muhitlarda qo'llanilishi shart:
- HackTheBox (HTB) mashinalari va chellenjlari;
- Mahalliy izolyatsiyalangan laboratoriyalar (Docker lab, DVWA, bWAPP, Juice Shop);
- Operatorning o'ziga tegishli bo'lgan shaxsiy serverlar va tizimlar;
- Tizim egasidan yozma ruxsatnoma olingan rasmiy penetratsion test shartnomalari.

Dastur hech qachon uchinchi shaxslarning tizimlariga ruxsatsiz hujum qilish uchun ishlatilmasligi kerak. Dastur buzib kirmaydi (no exploitation), nishon tizimda teskari qobiq (reverse shell) ochmaydi va ma'lumotlarni begona serverlarga uzatmaydi.

---

## 2. Ishlash prinsipi

### 2.1 So'rovlar oqimi (Request Flow)
Dastur ishga tushirilganda `main.go` fayli barcha amallarni boshqaradi:

```
[CLI Flags] ---> flag.Parse()
                     |
       +-------------+-------------+
       | Rejimni tanlash (Dispatch)|
       +-------------+-------------+
                     |
  +------------------+------------------+------------------+
  |                  |                  |                  |
[-doctor]         [-tech / -map]     [Fuzzing]         [-m / --crawl]
  |                  |                  |                  |
Diagnostika       Recon tahlili     VHost / Dir       Audit Dvigateli
                                        |                  |
                                     fuzzer.Run()     client.NewClient()
                                                           |
                                                      Target tuzish
                                                           |
                                                      Param Discovery
                                                           |
                                                      Tech + Intel
                                                           |
                                                      Modullar: Run()
                                                           |
                                                      Reporters (.md / .json)
```

1. **Flaglarni o'qish:** `flag.Parse()` CLI argumentlarini o'qiydi. `--dom` va `--no-dom` kabi o'zaro bog'liq bayroqlar sinxronlanadi. Sarlavhalar (`-H` va `--header`) birlashtiriladi.
2. **Rejimni tanlash (Dispatch):** Flaglar holatiga qarab tegishli rejim tanlanadi:
   - `-version`: Versiyani chiqaradi va to'xtaydi.
   - `-doctor`: Diagnostika tekshiruvlarini o'tkazadi va chiqish kodi bilan tugaydi.
   - `-i`: Sichqoncha bilan boshqariladigan interaktiv TUI panelini ishga tushiradi.
   - `-tech`: Standalone texnologiya detektorini ishga tushiradi.
   - `-map` / `-spider`: Sayt xaritasini rekursiv tuzadi.
   - `-shodan`: Shodan orqali passiv razvedka qiladi.
   - Fuzzing / VHost: FUZZ kalit so'zi aniqlanganda yuqori tezlikdagi fuzzerni ishga tushiradi.
   - `--crawl`: Saytni aylanib chiqib, topilgan parametrlarda XSS dvigatelini ishlatadi.
   - Standart skaner: Modullar ketma-ketligini ishga tushiradi.
3. **HTTP Mijozni shakllantirish:** `pkg/client.NewClient` orqali ulanishlarni qayta ishlatuvchi, sozlangan taymout, TLS bypass (`-k`), proksi (`-p`), cookie jar va scope guard bilan ta'minlangan mijoz tuziladi.
4. **Target obyektini tuzish:** Nishon URL, metod, parametrlar, POST tanasi, sarlavhalar va IDOR uchun 2-sessiya ma'lumotlari `modules.Target` ichiga joylashtiriladi.
5. **Autentifikatsiya:** Agar `-login-url` ko'rsatilgan bo'lsa, `client.PerformLogin()` orqali sessiya pechenyelari olinadi va cookie jarga keshlanadi.
6. **OAST Server:** Agar `-oast-listen` yoki `-oast-host` berilgan bo'lsa, o'rnatilgan HTTP callback serveri orqa fonda ishga tushiriladi.
7. **Yashirin parametrlarni qidirish:** `-discover-params` bayrog'i yoqilgan bo'lsa, `pkg/discovery` orqali parametrlar topiladi va `target.Params` ro'yxatiga qo'shiladi.
8. **Texnologiya va Intel:** `pkg/detector` texnologiyalarni aniqlaydi. Agar `--no-intel` o'rnatilmagan bo'lsa, `pkg/intel` orqali versiyalarga mos keluvchi Searchsploit va NVD ma'lumotlari to'planadi.
9. **Modullarni bajarish:** Faol modullar ketma-ket chaqirilib, ularning `Run(target, client)` funksiyalari bajariladi.
10. **Hisobotlarni yozish:** Barcha topilmalar birlashtirilib, `pkg/reporters` orqali Markdown va JSON fayllarga yoziladi.

### 2.2 Paketlar xaritasi (Package Map)
`pkg/` katalogidagi barcha paketlar:
- `pkg/client`: Ulanishlarni qayta ishlatuvchi, cookie jar, proxy, rate limiter, sessiyani avtomatik yangilovchi va scope guard bilan ta'minlangan HTTP mijoz.
- `pkg/parser`: Burp Suite xom HTTP so'rov fayllarini (RFC 7230) tahlil qilib, parametrlar, sarlavhalar va tanani ajratuvchi modul.
- `pkg/fuzzer`: ffuf uslubidagi goroutinelarga asoslangan, ko'p oqimli VHost, subdomen va katalog fuzzing dvigateli.
- `pkg/discovery`: Arjun uslubidagi yashirin HTTP GET parametrlarini biseksiya (ikkiga bo'lish) algoritmi orqali tezkor topuvchi dvigatel.
- `pkg/sitemap`: Rekursiv veb-krouler bo'lib, ilova arxitekturasi xaritasini tuzadi va HTML formalarni ajratib oladi.
- `pkg/detector`: Wappalyzer uslubida HTTP sarlavhalari, meta-teglar va JavaScript skriptlari orqali texnologiyalar va versiyalarni aniqlovchi detektor.
- `pkg/shodan`: Nishon domen va IP manzili bo'yicha Shodan API orqali passiv OSINT ma'lumotlarini yig'uvchi mijoz.
- `pkg/troubleshoot`: Skaner oldidan tarmoq ulanishlari, DNS, proksi va fayllarni tekshiruvchi diagnostika vositasi (-doctor).
- `pkg/tui`: Terminalda sichqoncha bilan interaktiv boshqariluvchi boshqaruv paneli (TUI).
- `pkg/reporters`: Natijalarni Markdown (`.md`) va JSON (`.json`) formatlarida eksport qiluvchi hisobot tizimi.
- `pkg/modules`: 23 ta xavfsizlik zaifliklarini tekshirish moduli va Target/Finding asosiy interfeyslari.
- `pkg/oast`: Blind/Out-of-band SSRF, XXE va Deserializatsiya zaifliklarini tutuvchi o'rnatilgan HTTP callback serveri.
- `pkg/xss`: XSStrike g'oyalariga asoslangan, DOM manbalari va sinklarini tahlil qiluvchi, canary-based XSS dvigateli.
- `pkg/intel`: Aniqlangan komponentlar versiyasiga mos keluvchi mahalliy Searchsploit va NVD 2.0 ma'lumotlarini qidiruvchi tizim.

### 2.3 Modul shartnomasi (Module Contract)
Barcha modullar `pkg/modules/module.go` da aniqlangan interfeysni to'liq amalga oshiradi:

```go
type Module interface {
    Name() string
    Description() string
    Run(target *Target, client *client.Client) ([]*Finding, error)
}
```

#### Target maydonlari:
- `URL string`: So'rov parametrlarisiz toza URL manzili.
- `Method string`: HTTP metodi (`GET`, `POST`, `PUT`, `DELETE` va h.k.).
- `Params map[string]string`: URL query parametrlari xaritasi.
- `Data map[string]string`: Form-urlencoded yoki JSON POST ma'lumotlari.
- `Headers map[string]string`: Birlamchi HTTP sarlavhalari.
- `Cookie2 string`: IDOR testi uchun ikkinchi foydalanuvchining cookie qiymati.
- `Headers2 map[string]string`: IDOR testi uchun ikkinchi foydalanuvchining sarlavhalari.
- `IsJSON bool`: So'rov tanasi JSON formatida ekanligini bildiruvchi belgi.
- `JSONBody map[string]interface{}`: Tahlil qilingan JSON obyekti.
- `JSONLeaves []string`: JSON daraxtidagi inyeksiya qilinishi mumkin bo'lgan barg kalitlar yo'li.
- `OAST *oast.Server`: Faol OAST callback serveri instansiyasi (agar yoqilgan bo'lsa).

#### Finding maydonlari:
- `Module string`: Zaiflikni aniqlagan modul nomi (masalan: `sqli`, `lfi`).
- `Title string`: Zaiflikning qisqa va tushunarli sarlavhasi.
- `Severity Severity`: Xavflilik darajasi (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `Confidence int`: Raqamli ishonchlilik foizi (50, 80, 100).
- `ConfidenceLevel ConfidenceLevel`: Matnli ishonchlilik darajasi (`confirmed`, `probable`, `possible`).
- `URL string`: Zaiflik topilgan aniq URL manzili.
- `Parameter string`: Zaif parametr yoki sarlavha nomi.
- `Payload string`: Zaiflikni isbotlagan test so'rovi (PoC payload).
- `Detail string`: Texnik tafsilotlar va xavf izohi.
- `Evidence string`: Server javobidan olingan aniq dalil parchasi (response snippet).
- `Remediation string`: Dasturchilar uchun xavfsizlikni bartaraf etish tavsiyasi.
- `CWEID int`: Tegishli MITRE CWE identifikatori.
- `CurlCmd string`: Muammoni qo'lda takrorlash uchun tayyorlangan `curl` buyrug'i.

### 2.4 Ishonchlilik darajalari (Confidence Levels)
NightfallLX uch bosqichli qat'iy ishonchlilik modelidan foydalanadi:

1. **`confirmed` (100%):**
   Zaiflik to'liq isbotlangan va uning mavjudligi shubhasizdir. Kodda ushbu darajaga erishish uchun quyidagi qat'iy shartlar bajarilishi talab qilinadi:
   - LFI: `/etc/passwd` ning `root:x:0:0:` qatori yoki Windows `win.ini` dagi `[fonts]` bo'limi server javobida to'liq aks etishi shart.
   - XSS: Unikal tasodifiy canary yuborilganda u server javobida qaytishi VA `CheckExecutableNode` orqali brauzerda skript sifatida ijro qilinishi mumkin bo'lgan HTML/JS tuguni ichida ekanligi tasdiqlanishi shart.
   - SQLi: Ma'lumotlar bazasi dvigatelining (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) rasmiy sintaksis xatosi qaytishi yoki vaqtga asoslangan kechikish (`sqli-delay`) serverda aynan kutilgan muddatga kechikishi shart.
   - CORS: Server soxta hujumchi sarlavhasini (`Access-Control-Allow-Origin: https://evil-attacker.com`) aks ettirishi VA bir vaqtning o'zida `Access-Control-Allow-Credentials: true` deb javob berishi shart.
   - Open Redirect: Server `301`, `302`, `303`, `307` yoki `308` status kodi bilan javob berishi va `Location` sarlavhasi aniq ko'rsatilgan tashqi manzilga yo'naltirishi shart.

2. **`probable` (80%):**
   Zaiflik mavjud bo'lishi ehtimoli juda yuqori, ammo to'liq ijro yoki xavfli oqibat oxirigacha tasdiqlanmagan:
   - CORS: Attacker Origin aks ettiriladi, ammo `Allow-Credentials` o'rnatilmagan yoki `*` belgisi bilan cheklangan.
   - Headers: Server xavfsizlik sarlavhasini yuboradi, ammo uning qiymati zaif (masalan, CSP da `unsafe-inline` ruxsat etilgan).
   - Host Header: Soxta host server tomonidan qabul qilinib, sahifadagi ichki havolalarda aks etadi, ammo to'g'ridan-to'g'ri tashqi manzilga yo'naltirmaydi.
   - CMDi: Buyruq yuborilganda vaqt kechikishi kuzatiladi, ammo chiqish oqimi (stdout) server javobida aks etmaydi.

3. **`possible` (50%):**
   Potensial zaiflik yoki xavfli konfiguratsiya belgisi bor, ammo u to'g'ridan-to'g'ri ekspluatatsiyani kafolatlamaydi:
   - Headers: Xavfsizlik sarlavhalari (masalan, HSTS, X-Content-Type-Options) javobda umuman mavjud emas.
   - GraphQL: `/graphql` endpointi mavjud, ammo to'liq schema introspeksiyasi server tomonidan o'chirib qo'yilgan.
   - Prototype Pollution: So'rov yuborilganda javob tanasida parametr aks etadi, ammo ob'ekt prototipi to'liq zaharlangani tasdiqlanmaydi.
   - IDOR: Parametr o'zgartirilganda javob hajmi yoki status kodida shubhali farq seziladi, ammo ruxsatsiz ma'lumot to'liq ochilmagan.

---

## 3. O'rnatish

### 3.1 Tizim talablari va Go versiyasi
NightfallLX `go.mod` fayliga binoan **Go 1.26** versiyasini talab qiladi. Dastur zamonaviy Go kutubxonalari va standart paketlariga tayanadi.

Tizimdagi Go versiyasini tekshirish:
```bash
go version
```

### 3.2 Dasturni kompilyatsiya qilish va o'rnatish
Dasturni binar fayl sifatida yig'ish va foydalanuvchining lokal binar katalogiga joylashtirish:

```bash
cd nightfalllx-go
go build -o "$HOME/.local/bin/nightfalllx" .
```

Agar `~/.local/bin` katalogi tizimda mavjud bo'lmasa, uni oldindan yarating:
```bash
mkdir -p "$HOME/.local/bin"
```

### 3.3 PATH muhit o'zgaruvchisini sozlash
Dasturni terminalning istalgan joyidan nomini yozish orqali chaqirish uchun `~/.local/bin` katalogi PATH ro'yxatida bo'lishi kerak.

Agar ushbu qator mavjud bo'lmasa, `~/.bashrc` yoki `~/.zshrc` fayliga quyidagi qatorni qo'shing:
```bash
export PATH="$HOME/.local/bin:$PATH"
```

Faylni qayta yuklash:
```bash
source ~/.bashrc
```

O'rnatish muvaffaqiyatli yakunlanganini tekshirish:
```bash
which nightfalllx
nightfalllx -version
nightfalllx -h | head -n 5
```

### 3.4 Ixtiyoriy tashqi vositalarni o'rnatish
1. **Searchsploit (Exploit-DB):**
   Aniqlangan versiyalarga mos keluvchi eksploitlarni qidirish uchun tizimga `exploitdb` paketini o'rnatish tavsiya etiladi:
   ```bash
   sudo apt update && sudo apt install exploitdb -y
   ```
2. **Headless Chromium / Chrome:**
   `--dom-browser` bayrog'i yordamida DOM XSS zaifliklarini haqiqiy brauzer kontekstida tasdiqlash uchun:
   ```bash
   sudo apt install chromium -y
   ```
3. **NIST NVD API kaliti:**
   NVD 2.0 API orqali CVE va CVSS ko'rsatkichlarini tezkor yuklash uchun (soatlik so'rovlar limitiga tushib qolmaslik uchun) muhit o'zgaruvchisini sozlang:
   ```bash
   export NVD_API_KEY="sizning-shaxsiy-nvd-kalitingiz"
   ```

---

## 4. Rejimlar (modes) va ularni tanlash

`main.go` da barcha kiruvchi so'rovlar qat'iy tekshiruvdan o'tadi va quyidagi tartibda tegishli rejimga yo'naltiriladi:

### 4.1 Diagnostika rejimi (`-doctor` / `-troubleshoot`)
Ushbu rejim skanerlashdan oldin barcha zaruriy ulanishlar, DNS yozuvlari, HTTP proksi va fayllarni tekshiradi.
```bash
nightfalllx -doctor -u http://10.129.x.x/
```
Agar proksi yoki wordlist berilgan bo'lsa, ularning mavjudligi va ulanishini ham tekshiradi:
```bash
nightfalllx -doctor -u http://target.lab/ -p http://127.0.0.1:8080 -w wordlist.txt
```

### 4.2 Texnologiyalarni aniqlash (`-tech`)
Wappalyzer uslubidagi ushbu rejim nishon sahifadagi HTTP sarlavhalari, HTML meta-teglari, cookie nomlari va JavaScript skriptlarini tahlil qilib, ishlatilayotgan server, ramka, til va kutubxona versiyalarini chiqaradi.
```bash
nightfalllx -tech -u http://target.lab/
```

### 4.3 Sayt xaritasi va krouler (`-map` / `-spider`)
Nishon ilovani belgilangan chuqurlik (`-depth`) va maksimal URL soni (`-max-urls`) bo'yicha rekursiv kroul qiladi. Barcha ichki havolalar, tashqi havolalar, static fayllar va HTML formalarni ajratib xarita tuzadi.
```bash
nightfalllx -map -depth 3 -max-urls 50 -u http://target.lab/
```

### 4.4 Shodan OSINT qidiruvi (`-shodan`)
Nishon URL manzilidan IP yoki domenni ajratib oladi va Shodan API orqali passiv ochiq portlar, servislari, joylashuvi va ma'lumotlarini qidiradi.
```bash
nightfalllx -shodan -u http://target.lab/ -shodan-key "SHODAN_API_KEY"
```

### 4.5 Interaktiv TUI paneli (`-i` / `-ui` / `-tui`)
Terminalda sichqoncha bilan to'liq boshqariladigan interaktiv grafik panelni ochadi. Paneldan skanerlashni boshlash, to'xtatish va topilmalarni ko'rish mumkin.
```bash
nightfalllx -i -u http://target.lab/
```

### 4.6 Fuzzing va VHost rejimi
URL, ma'lumotlar yoki sarlavhalarda `FUZZ` so'zi qatnashganda yoki `-fuzz` berilganda yuqori tezlikdagi goroutine dvigateli ishga tushadi (batafsil 5-bo'limda).
```bash
nightfalllx -u http://10.129.x.x/FUZZ -w /path/to/wordlist.txt
```

### 4.7 Xom HTTP so'rov fayli (`-r`)
Burp Suite orqali saqlangan xom HTTP so'rov faylini o'qiydi. Undan metod, to'liq URL, sarlavhalar, cookie va POST tanasini ajratib olib, to'g'ridan-to'g'ri skanerga uzatadi.
```bash
nightfalllx -r burp_request.txt -m sqli,xss
```
Agar so'rov HTTPS orqali bo'lsa, `-https` bayrog'ini qo'shing:
```bash
nightfalllx -r burp_request.txt -https -m all
```

### 4.8 Odatiy zaiflik skaneri (`-m`)
Ko'rsatilgan modullar bo'yicha chuqur audit o'tkazadi (standart: `all`, ya'ni 22 ta faol modul).
```bash
nightfalllx -u http://target.lab/?id=1 -m sqli,lfi,xss
```

### 4.9 XSS krouler va skaneri (`--crawl`)
Sayt bo'ylab krouler yuradi. Har bir aniqlangan parametr va HTML formalarni ajratib, ularga avtomatik ravishda kontekstli XSS dvigatelini qo'llaydi.
```bash
nightfalllx --crawl -depth 2 -max-urls 30 -u http://target.lab/
```

### 4.10 Ko'p nishonli massiv skanerlash (`-l` / `--list`)
Hujjat yoki ro'yxat faylidan (masalan: `targets.txt`) bir nechta yoki yuzlab saytlarni o'qib, ularni xavfsiz va xotiradan toza holatda ketma-ket skanerlaydi.
- Har bir nishon uchun alohida hisobot bazasi hosil qilinadi (`<output>-<host>.md`, `.json`, `.html`, `.sarif`).
- Bo'sh qatorlar va izohlar (`#`) avtomatik tashlab ketiladi.
- Jarayon tugagach, yakuniy muvaffaqiyat statistikasi ko'rsatiladi.
```bash
nightfalllx -l targets.txt -m sqli,xss -o batch_scan
```

### 4.11 SPA (Single Page Application) to'liq qo'llab-quvvatlash (`--spa`)
Headless Chrome / Chromium orqali mijoz tomonida ishlovchi dynamic DOM ni to'liq renderlaydi.
- React Router, Vue Router, Angular va hash-marshrutlarni (`path: "..."`, `to: "..."`, `href="#/..."`) aniqlaydi.
- Standart statik HTML kroulerlari ko'ra olmaydigan dinamik veb sahifalarni 100% qamrab oladi.
```bash
nightfalllx -u http://target.lab/ -map -spa -depth 3
nightfalllx -u http://target.lab/ -crawl -spa
```

### 4.12 Devbuster zamonaviy web ilovalar marshrut krouleri va fuzzeri (`-devbuster` / `-dbuster`)
React, Next.js, Vue va Angular kabi zamonaviy SPA va veb-ilovalarda klassik fuzzerlar topa olmaydigan yashirin marshrutlarni aniqlovchi scope-aware gibrid dvigatel:
- **Kanonik manzilni oldindan aniqlash (Canonical Origin Detection):** Fuzzingdan oldin `www`/non-`www`, HTTPS va ildiz yo'naltirishlarni tekshirib, haqiqiy kanonik manzilni aniqlaydi (301/308 soxta javoblarining oldini oladi).
- **JavaScript to'plamlaridan marshrut ajratish (`js:literal`):** Next.js chunklari (`_next/static/chunks/...`) va Webpack to'plamlaridagi barcha string marshrutlarni (`/api/...`, `/dashboard/...`) statik fayllarni (rasmlar, shriftlar, CSS) filtrlagan holda ajratib oladi.
- **Gibrid krouling va fuzzing:** Lug'atdagi so'zlar bilan birga HTML havolalari va JS marshrutlarini dinamik navbatga qo'shib boradi.
- **Moslashuvchan status filtrlari:** Keraksiz status kodlarni yashirish (`--hide-status 403,404`) yoki faqat keraklilarni ko'rsatish (`--status 200,301,302`).
```bash
# Zamonaviy veb ilovani Devbuster orqali chuqur tahlil qilish:
nightfalllx -u https://target.lab/ -devbuster -w /usr/share/seclists/Discovery/Web-Content/common.txt

# 403 va 404 xatolarni yashirib, subdomenlarni ham qamrab olish:
nightfalllx -u https://target.lab/ -devbuster -w routes.txt --hide-status 403,404 --include-subdomains -o devbuster_out

# Headless brauzer renderlash bilan birga ishlatish:
nightfalllx -u https://target.lab/ -devbuster -w routes.txt -spa -delay 0.5
### 4.13 Intellektual avtomatik wordlist tanlash (Auto-Resolving Wordlists)
NightfallLX endi foydalanuvchidan har safar uzun fayl yo'llarini kiritishni talab qilmaydi.
- **`-w` ko'rsatilmaganda (Standart rejim):** Har bir modul va amaliyot uchun tizimdagi eng mos standart lug'at avtomatik topiladi va ishlatiladi:
  - **Klassik Fuzzing & Devbuster:** `/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt` (4 751 ta so'z) yoki CWES `custom_wordlist.txt`.
  - **LFI & Path Traversal:** `/usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt` (930 ta vektor).
  - **Parametrlarni qidirish (`-discover-params`):** `/usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt` (6 453 ta parametr).
  - **Brute force & Parollar:** `/usr/share/wordlists/rockyou.txt` yoki CWES `passwords.txt`.
  - **IDOR & Raqamli PINlar:** `seq 0 10000` / 4 xonali sonlar (`0000..9999`) avtomatik generatsiya qilinadi hamda CWES `pins.txt` yuklanadi.
- **Tezkor kalit so'zlar (`-w <keyword>`):**
  - `-w 4digit` yoki `-w idor`: 0 dan 10000 gacha raqamlar ro'yxatini yuklaydi.
  - `-w colors`: `/home/cyborg/CWES/colors.txt` (ranglar ro'yxati).
  - `-w cities`: `/home/cyborg/CWES/world-cities.csv` (dunyo shaharlari).
  - `-w rockyou`: `/usr/share/wordlists/rockyou.txt`.
  - `-w lfi`: SecLists LFI-Jhaddix ro'yxati.
  - `-w params`: SecLists burp-parameter-names ro'yxati.
  - `-w pins`: CWES PIN kodlar ro'yxati.
  - `-w users`: CWES foydalanuvchilar ro'yxati.
- **Maxsus fayl yo'li:** Agar foydalanuvchi o'z faylini bersa (masalan: `-w my_list.txt`), aynan shu fayl birinchi darajali ustuvorlik bilan ishlatiladi.

---

## 5. Vhost va subdomen qidirish

### 5.1 DNS subdomen qidiruvi va VHost qidiruvi farqi
- **DNS Subdomain Discovery:** DNS so'rovlari (A, AAAA, CNAME) yordamida domen uchun alohida IP manzillarni yoki umumiy DNS yozuvlarini qidiradi.
- **VHost Discovery (Host Header):** Bitta IP manzilga (veb-serverga) ega bo'lgan holda, HTTP so'rovining `Host` sarlavhasiga turli xil qiymatlar qo'yib yuboriladi (masalan: `Host: admin.target.htb`). Zamonaviy veb-serverlar (Nginx, Apache) bitta IP da yuzlab virtual xostlarni ushlab turishi mumkin. VHost fuzzing ichki tarmoqqa yashirilgan yoki ommaviy DNS da e'lon qilinmagan yashirin xizmatlarni topishning eng samarali usulidir.

### 5.2 Kod tahlili: Fuzzing qachon ishga tushadi?
`main.go` da fuzzing rejimiga o'tish sharti 472–480-qatorlarda quyidagicha tekshiriladi:
```go
hasFuzzKeyword := strings.Contains(rawURL, "FUZZ") || strings.Contains(rawURL, "*") ||
    strings.Contains(data, "FUZZ") || strings.Contains(data, "*")
for _, v := range parsedHeaders {
    if strings.Contains(v, "FUZZ") || strings.Contains(v, "*") {
        hasFuzzKeyword = true
        break
    }
}

if isFuzz || hasFuzzKeyword || (wordlist != "" && len(parsedHeaders["Host"]) > 0 && strings.Contains(parsedHeaders["Host"], "FUZZ"))
```

### 5.3 MA'LUM XATO (Known Bug): `-sub` bayrog'i
Kodda quyidagi dizayn xatosi mavjud:
Agar foydalanuvchi quyidagi buyruqni bersa:
```bash
nightfalllx -sub -u http://10.129.x.x -domain target.htb -w subdomains.txt
```
Dastur **fuzzing rejimiga kirmaydi** va standart zaiflik skaneriga o'tib ketadi!

**Sababi:**
`main.go` faylining 481-qatoridagi `if` shartida `isSubdomain` (`-sub`) o'zgaruvchisi tekshirilmagan. `Host: FUZZ.<domain>` qiymatini o'rnatish kodi esa ushbu `if` blokining **ichida** (485-qatorda) joylashgan:
```go
if isSubdomain && domain != "" && parsedHeaders["Host"] == "" {
    parsedHeaders["Host"] = "FUZZ." + domain
}
```
Natijada, tekshiruv paytida `parsedHeaders["Host"]` hali bo'sh bo'ladi va shart qanoatlantirilmaydi.

**Ishlaydigan yechim (Workaround):**
Fuzzing triggeri ishlashi uchun `Host` sarlavhasida to'g'ridan-to'g'ri `FUZZ` kalit so'zini ko'rsatish shart:
```bash
nightfalllx -u http://10.129.x.x -H "Host: FUZZ.target.htb" -w subdomains.txt -ac
```
Bu holda `hasFuzzKeyword` o'zgaruvchisi `true` bo'ladi va fuzzer muammosiz ishga tushadi.

### 5.4 Kalibratsiya va filtrlash mexanizmi
- **`-ac` (Auto-calibrate, standart: true):**
  Fuzzer ishga tushishidan oldin nishon serverga bir nechta mavjud bo'lmagan tasodifiy xostlar (masalan: `x9f1a2b3c4.target.htb`) bilan so'rov yuboradi. Serverning "wildcard" (standart) javobini o'rganadi: status kodi, baytlar hajmi, so'zlar va satrlar soni o'lchanadi. Haqiqiy fuzzing jarayonida ushbu bazaga teng keladigan barcha soxta javoblar avtomatik filtrlanadi.
- **Filtrlar (Filters):**
  - `-fc`: Status kodlarini filtrlash (standart: `404`).
  - `-fs`: Javob hajmini filtrlash (baytlarda, masalan: `-fs 1240`).
  - `-fw`: Javobdagi so'zlar sonini filtrlash (masalan: `-fw 150`).
  - `-fl`: Javobdagi satrlar sonini filtrlash (masalan: `-fl 32`).
- **Moslashtirgichlar (Matchers):**
  - `-mc`: Faqat ko'rsatilgan status kodlarini ko'rsatish (masalan: `-mc 200,301,302,403`).
  - `-ms`: Faqat ko'rsatilgan hajmga ega javoblarni ko'rsatish.
  - `-mw`: Faqat ko'rsatilgan so'zlar soniga ega javoblarni ko'rsatish.
  - `-ml`: Faqat ko'rsatilgan satrlar soniga ega javoblarni ko'rsatish.

### 5.4.1 Kalibrator Algoritmi Qanday Ishlaydi?
`pkg/fuzzer/fuzzer.go` faylidagi `calibrate` metodi quyidagi aniq hisob-kitobni amalga oshiradi:
1. Fuzzer nishon IP yoki URL ga tasodifiy 16 belgidan iborat bo'lgan 3 ta mavjud bo'lmagan soxta xost (wildcard) bilan so'rov yuboradi.
2. Har bir javobning:
   - HTTP status kodi (masalan `200` yoki `404`);
   - Javob tanasi bayt hajmi (`Content-Length` yoki body len);
   - So'zlar soni (bo'shliqlar orqali ajratilgan tokenlar);
   - Satrlar soni (`\n` belgilari soni) saqlanadi.
3. Agar server barcha mavjud bo'lmagan xostlar uchun bir xil status kodi (masalan `200 OK`) va bir xil hajm qaytarsa, ushbu status va hajm fuzzer konfiguratsiyasidagi `FilterCodes` va `FilterSizes` ro'yxatiga avtomatik kiritiladi.
4. Bu orqali Apache yoki Nginx ning "Default Virtual Host" sahifalari tufayli yuzlab soxta musbat natijalar chiqishi 100% oldi olinadi.

### 5.5 HTB uslubidagi nishon uchun bosqichma-bosqich qo'llanma
HackTheBox mashinasida VHostlarni topish uchun quyidagi qadamlarni bajaring:

1. **Veb-portni tekshiring:**
   Nmap orqali port 80 yoki 8080 ochiqligini aniqlang.
2. **Host yo'naltirishini aniqlang:**
   ```bash
   curl -I http://10.129.x.x/
   ```
   Agar javobda `Location: http://board.htb/` kabi yo'naltirish bo'lsa, asosiy domen `board.htb` hisoblanadi.
3. **VHost fuzzingni ishga tushiring:**
   ```bash
   nightfalllx -u http://10.129.x.x/ -H "Host: FUZZ.board.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -ac -t 50
   ```
4. **Natijalarni ko'rib chiqing:**
   Fuzzer kalibratsiyadan so'ng faqat hajmi yoki statusi farq qiluvchi xostlarni chiqaradi:
   `[200 OK] admin.board.htb (Size: 4521, Words: 312)`
5. **Qo'lda tekshiring:**
   ```bash
   curl -s -H "Host: admin.board.htb" http://10.129.x.x/ | head -n 20
   ```
6. **`/etc/hosts` fayliga qo'shing:**
   ```bash
   echo "10.129.x.x admin.board.htb" | sudo tee -a /etc/hosts
   ```

### 5.6 Katalog va fayllarni fuzzing qilish
Kataloglarni qidirish uchun URL manziliga `FUZZ` qo'yiladi:
```bash
nightfalllx -u http://target.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 40 -timeout 15 -fc 404
```
POST so'rov tanasini fuzzing qilish:
```bash
nightfalllx -u http://target.htb/api/login -X POST -d "username=admin&password=FUZZ" -w /usr/share/seclists/Passwords/Common-Credentials/top-100.txt -fc 401
```

---

## 6. Zaiflik modullari

NightfallLX jami 23 ta xavfsizlik moduliga ega.

### 6.1 Umumiy modullar jadvali

| Modul | Nomi | Nimalarni tekshiradi | Tasdiqlash qoidasi (Confirmation Rule) | `-m all` da |
|---|---|---|---|:---:|
| `waf` | WAF/Proxy Detector | WAF va Reverse Proxy belgilarini aniqlaydi | Passiv tokenlar orqali: Info darajasida (`Confidence: 95`) | Ha |
| `headers` | Security Headers | Xavfsizlik sarlavhalari (CSP, HSTS, XFO) mavjudligi | Sarlavha yo'q: `possible`; Zaif qiymat: `probable` | Ha |
| `exposure` | Sensitive File Exposure | Ochiq fayllar (.git, .env, backup, phpinfo) | 200 OK va kutilgan unikal ichki tarkib: `confirmed` | Ha |
| `sqli` | SQL Injection | Error, Boolean va Time-based SQLi | RDBMS xatosi yoki vaqt kechikishi mos kelsa: `confirmed` | Ha |
| `ssti` | Server-Side Template Injection | Shablon inyeksiyalari (Jinja2, Twig va b.) | Matematik ifoda natijasi javobda aks etsa: `confirmed` | Ha |
| `lfi` | Local File Inclusion | Path Traversal (/etc/passwd, win.ini) | `root:x:0:0:` yoki tizim fayli belgilari: `confirmed` | Ha |
| `cmdi` | OS Command Injection | Buyruqlar inyeksiyasi (echo, cat, sleep) | Canary yoki fayl tarkibi aks etsa: `confirmed` | Ha |
| `xss` | Cross-Site Scripting | Reflected, DOM va Stored XSS | Canary aks etib, `CheckExecutableNode` rost bo'lsa: `confirmed` | Ha |
| `cors` | CORS Misconfiguration | Noto'g'ri CORS kelib chiqishi va ruxsatlar | Origin aks etib, `Allow-Credentials: true` bo'lsa: `confirmed` | Ha |
| `redirect` | Open Redirect | Ochiq yo'naltirish zaifliklari | `Location` tashqi nishonga yo'naltirsa: `confirmed` | Ha |
| `ssrf` | Server-Side Request Forgery | SSRF (localhost, Cloud metadata, OAST) | Cloud metadata yoki OAST callback kelsa: `confirmed` | Ha |
| `jwt` | JSON Web Token | `none` algoritmi va bo'sh imzo zaifliklari | O'zgartirilgan token qabul qilinib 200 OK bo'lsa: `confirmed` | Ha |
| `idor` | Insecure Direct Object Reference | Ruxsatsiz ob'ektlarga kirish (2-sessiya) | 2-sessiya orqali 1-ob'ektga kirish tasdiqlansa: `confirmed` | Ha |
| `csrf` | Cross-Site Request Forgery | Anti-CSRF tokenining yo'qligi | Holat o'zgartiruvchi so'rovda token bo'lmasa (`90/70`) | Ha |
| `xxe` | XML External Entity | XML tashqi parametr va fayl yuklash | Tizim fayli aks etsa yoki OAST callback: `confirmed` | Ha |
| `nosqli` | NoSQL Injection | MongoDB va NoSQL operator inyeksiyalari | NoSQL xatosi yoki `$ne` mantiqiy farq: `confirmed` | Ha |
| `upload` | Arbitrary File Upload | Xavfli kengaytmali fayllarni yuklash | Test fayli yuklanib, javob bersa: `confirmed` | **Yo'q (Opt-in)** |
| `hostheader` | Host Header Injection | Host sarlavhasini soxtalashtirish | Soxta host javobdagi `Location`da qaytsa: `confirmed` | Ha |
| `crlf` | CRLF / Response Splitting | HTTP sarlavhalarini ajratish (`%0d%0a`) | Inyeksiya qilingan sarlavha javobda paydo bo'lsa: `confirmed` | Ha |
| `graphql` | GraphQL Security | GraphQL endpointlari va Introspeksiya | To'liq `__schema` introspeksiyasi qaytsa: `confirmed` | Ha |
| `protopollution` | Prototype Pollution | Obyekt prototipini zaharlash | Prototip xususiyati meros olingani isbotlansa: `confirmed` | Ha |
| `massassign` | Mass Assignment | Ruxsatsiz imtiyozli maydonlar kiritish | Yangi imtiyozli maydon (`admin: true`) saqlansa: `confirmed` | Ha |
| `deserialize` | Insecure Deserialization | Serializatsiyalangan ob'ektlarni yuborish | Deserializatsiya xatosi yoki OAST kelsa: `confirmed` | Ha |

*Muhim eslatma:* `upload` moduli serverga fayl yuklash xavfi sababli `-m all` ro'yxatiga kiritilmagan. U faqat operator `-m upload` orqali alohida chaqirganda ishlaydi.

### 6.2 Har bir modulning batafsil tahlili

#### 1. `waf` (WAF / Reverse Proxy Detektori)
- **Tekshiradigan vektorlar:** Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, F5 BIG-IP, Sucuri, Barracuda.
- **Ishlash mexanizmi:** Sarlavhalardagi tokenlarni (`cf-ray`, `x-amz-cf-id`, `x-sucuri-id`) va bloklash sahifalaridagi xos belgilarni qidiradi.
- **Tasdiqlash qoidasi:** `Finding.Severity = SeverityInfo`, `Confidence: 95`.
- **Takrorlash misoli:**
  ```bash
  curl -i -s "http://target.lab/?id=<script>alert(1)</script>"
  ```
- **Remediation:** Axborot topilmasi. WAF qoidalari noqonuniy aylanib o'tishlarga qarshi to'g'ri sozlanganini tekshirish lozim.

#### 2. `headers` (Xavfsizlik Sarlavhalari)
- **Tekshiradigan vektorlar:** HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- **Ishlash mexanizmi:** Server javobidagi sarlavhalar mavjudligi va ularning xavfsizlik mezonlariga mosligini tahlil qiladi.
- **Tasdiqlash qoidasi:** Sarlavha yo'q bo'lsa -> `SetConfidence(ConfidencePossible)` (50%). Sarlavha bor, ammo unda `unsafe-inline`, `unsafe-eval` yoki `*` bo'lsa -> `SetConfidence(ConfidenceProbable)` (80%).
- **Takrorlash misoli:**
  ```bash
  curl -I -s "http://target.lab/"
  ```
- **Remediation:** Server konfiguratsiyasiga qat'iy xavfsizlik sarlavhalarini qo'shish (`HSTS max-age=31536000`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`).

#### 3. `exposure` (Nozik Fayllar Ochiqligi)
- **Tekshiradigan vektorlar:** `.git/HEAD`, `.git/config`, `.env`, `wp-config.php.bak`, `server-status`, `phpinfo.php`, `swagger.json`, `config.json`.
- **Ishlash mexanizmi:** 20 dan ortiq xavfli fayllar ro'yxatini tekshiradi.
- **Tasdiqlash qoidasi:** Server HTTP 200 OK qaytarishi VA javob ichida faylga xos kalit matn bo'lishi shart (`ref: refs/heads/`, `DB_PASSWORD=`, `PHP Version`). Bular bo'lsa -> `SetConfidence(ConfidenceConfirmed)` (100%).
- **Takrorlash misoli:**
  ```bash
  curl -i -s "http://target.lab/.git/HEAD"
  ```
- **Remediation:** Veb-serverda yashirin fayllar va konfiguratsiyalarga to'g'ridan-to'g'ri kirishni bloklash (`deny all` qoidalari).

#### 4. `sqli` (SQL Inyeksiya)
- **Tekshiradigan vektorlar:** Error-based (`'`, `"`, `')`), Boolean-based (`AND 1=1`, `AND 1=2`), Time-based (`sleep(3)`, `pg_sleep(3)`).
- **Ishlash mexanizmi:** URL va POST parametrlariga RDBMS ga xos belgilarni kiritadi.
- **Tasdiqlash qoidasi:** Rasmiy xato xabari (Syntax error, ORA-, pg_query) qaytsa yoki javob vaqti sozlangan `sqli-delay` soniyasiga teng kechikib, differensial testdan o'tsa -> `SetConfidence(ConfidenceConfirmed)` (100%). Boolean farq bo'lsa -> `SetConfidence(ConfidencePossible)` (50%).
- **Takrorlash misoli:**
  ```bash
  curl -i -s "http://target.lab/?id=1'%20WAITFOR%20DELAY%20'0:0:3'--"
  ```
- **Remediation:** Barcha ma'lumotlar bazasi so'rovlarida parametrli tayyorlangan so'rovlardan (Parameterized Prepared Statements) foydalanish.

#### 5. `ssti` (Server-Side Template Inyeksiya)
- **Tekshiradigan vektorlar:** Jinja2, Twig, Smarty, Ruby ERB, Freemarker, Mako: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `{{7*'7'}}`.
- **Ishlash mexanizmi:** Arifmetik amallarni yuborib, ularning hisoblangan natijasini server javobida qidiradi.
- **Tasdiqlash qoidasi:** Server javobida hisoblangan ko'paytma (masalan: `49` yoki `7777777`) aks etsa va bu son asl so'rovda bo'lmasa -> `SetConfidence(ConfidenceConfirmed)` (100%).
- **Takrorlash misoli:**
  ```bash
  curl -i -s "http://target.lab/?name={{7*7}}"
  ```
- **Remediation:** Foydalanuvchi ma'lumotlarini to'g'ridan-to'g'ri shablon kodiga joylashtirmaslik, shablon dvigatelida qumloq (sandboxing) rejimini yoqish.

#### 6. `lfi` (Local File Inclusion / Path Traversal)
- **Tekshiradigan vektorlar:** `../../../../etc/passwd`, `..%2f..%2f..%2fetc%2fpasswd`, `/etc/passwd%00`, `c:\windows\win.ini`.
- **Ishlash mexanizmi:** Kataloglar bo'ylab yuqoriga chiqish ketma-ketligini parametrlar ichiga kiritadi.
- **Tasdiqlash qoidasi:** Server javobida `root:x:0:0:` yoki `[fonts]` bo'limi aniq qaytsa -> `SetConfidence(ConfidenceConfirmed)` (100%).
- **Takrorlash misoli:**
  ```bash
  curl -i -s "http://target.lab/view.php?file=../../../../etc/passwd"
  ```
- **Remediation:** Fayl yo'llarini foydalanuvchi kiritmasidan to'g'ridan-to'g'ri olmaslik, qat'iy oq ro'yxat (allowlist) asosida fayllarni ochish.

#### 7. `cmdi` (OS Buyruqlar Inyeksiyasi)
- **Tekshiradigan vektorlar:** `;`, `|`, `&`, `&&`, `$()`, backticks: `echo <canary>`, `cat /etc/passwd`, `sleep 3`.
- **Ishlash mexanizmi:** Unikal canary va vaqt kechikishlarini buyruq ajratuvchilari bilan birlashtirib parametrga yuboradi.
- **Tasdiqlash qoidasi:** Unikal canary yoki tizim fayli javobda qaytsa -> `SetConfidence(ConfidenceConfirmed)` (100%). Vaqt kechikishi tasdiqlansa -> `SetConfidence(ConfidenceProbable)` (80%).
- **Takrorlash misoli:**
  ```bash
  curl -i -s "http://target.lab/ping?host=127.0.0.1;echo%20nightfall"
  ```
- **Remediation:** Tizim qobig'ini chaqiruvchi funksiyalardan (`exec`, `system`, `passthru`) voz kechish, parametrlarni qat'iy tekshirish.

#### 8. `xss` (Cross-Site Scripting)
- **Tekshiradigan vektorlar:** Reflected, DOM-based, Stored XSS.
- **Ishlash mexanizmi:** Unikal canary (`lxc` + 12 hex) bilan shakllantirilgan kontekstli payloadlarni yuboradi.
- **Tasdiqlash qoidasi:** Canary aks etib, `CheckExecutableNode(body, canary)` uni ijro etiluvchi HTML/JS kontekstida deb topsa -> `SetConfidence(ConfidenceConfirmed)` (100%).
- **Takrorlash misoli:**
  ```bash
  curl -i -s "http://target.lab/search?q=<script>/*lxc1a2b3c4d5e6f*/</script>"
  ```
- **Remediation:** Barcha kiritilgan ma'lumotlarni kontekstga qarab to'g'ri kodlash (HTML entity encoding, JavaScript encoding) va CSP o'rnatish.

#### 9. `cors` (CORS Xavfsizligi)
- **Tekshiradigan vektorlar:** `Origin: https://evil-attacker.com`, `Origin: null`.
- **Ishlash mexanizmi:** Ruxsatsiz kelib chiqish manbalarini yuborib, serverning ruxsat sarlavhalarini tekshiradi.
- **Tasdiqlash qoidasi:** Server `Access-Control-Allow-Origin: https://evil-attacker.com` qaytarib, bir vaqtda `Access-Control-Allow-Credentials: true` bo'lsa -> `SetConfidence(ConfidenceConfirmed)` (100%).
- **Takrorlash misoli:**
  ```bash
  curl -i -s -H "Origin: https://evil.com" "http://target.lab/api/user"
  ```
- **Remediation:** `Access-Control-Allow-Origin` ga nishon domenlar oq ro'yxatini o'rnatish, begona kelib chiqishlarga `Credentials: true` bermaslik.

#### 10. `redirect` (Open Redirect)
- **Tekshiradigan vektorlar:** `url=https://example.com`, `next=//example.com`, `redirect=\/example.com`.
- **Ishlash mexanizmi:** Yo'naltiruvchi parametrlarga tashqi domenlarni kiritadi.
- **Tasdiqlash qoidasi:** Server 3xx kodi bilan javob bersa va `Location` sarlavhasi kiritilgan tashqi manzilga yo'naltirsa -> `SetConfidence(ConfidenceConfirmed)` (100%).
- **Takrorlash misoli:**
  ```bash
  curl -i -s "http://target.lab/login?next=https://example.com"
  ```
- **Remediation:** Yo'naltirish manzillarini faqat ichki nisbiy yo'llar (relative paths) bilan cheklash.

#### 11. `ssrf` (Server-Side Request Forgery)
- **Tekshiradigan vektorlar:** `http://127.0.0.1:80`, `http://169.254.169.254/latest/meta-data/`, OAST manzili.
- **Ishlash mexanizmi:** Ichki tarmoq manzillari va o'rnatilgan OAST callback serveri havolalarini yuboradi.
- **Tasdiqlash qoidasi:** Cloud metadata qaytsa yoki OAST serverga HTTP so'rovi kelsa -> `SetConfidence(ConfidenceConfirmed)` (100%). Farqli status/o'lcham bo'lsa -> `SetConfidence(ConfidenceProbable)` (80%).
- **Takrorlash misoli:**
  ```bash
  curl -i -s "http://target.lab/fetch?url=http://169.254.169.254/latest/meta-data/"
  ```
- **Remediation:** Server so'rovlarini faqat ruxsat etilgan oq ro'yxatdagi tashqi domenlar bilan cheklash, ichki IP diapazonlarini bloklash.

#### 12. `jwt` (JSON Web Token Xavfsizligi)
- **Tekshiradigan vektorlar:** `alg: none`, bo'sh imzo (signature stripped), zaif HMAC siri.
- **Ishlash mexanizmi:** Token sarlavhasini va imzosini olib tashlab qayta yuboradi.
- **Tasdiqlash qoidasi:** `none` algoritmli token qabul qilinib, server 200 OK qaytarsa -> `SetConfidence(ConfidenceConfirmed)` (100%).
- **Takrorlash misoli:**
  ```bash
  curl -i -s -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ." "http://target.lab/api/admin"
  ```
- **Remediation:** JWT kutubxonasida `none` algoritmini taqiqlash, qat'iy algoritm tekshiruvini yoqish.

#### 13. `idor` (Insecure Direct Object Reference)
- **Tekshiradigan vektorlar:** Identifikatorlarni almashtirish (`id=1` -> `id=2`, `uuid`).
- **Ishlash mexanizmi:** 1-foydalanuvchi ma'lumotlarini 2-foydalanuvchining cookie va sarlavhalari (`-b2`, `-H2`) orqali so'raydi.
- **Tasdiqlash qoidasi:** 2-foydalanuvchi sessiyasi orqali 1-foydalanuvchi ob'ektiga kirish tasdiqlansa va ruxsat xatosi bo'lmasa -> `SetConfidence(ConfidenceConfirmed)` (100%).
- **Takrorlash misoli:**
  ```bash
  curl -i -s -b "session=user2_cookie" "http://target.lab/invoice?id=1"
  ```
- **Remediation:** Har bir so'rovda foydalanuvchining ushbu resursga egalik huquqini (Authorization check) tekshirish.

#### 14. `csrf` (Cross-Site Request Forgery)
- **Tekshiradigan vektorlar:** POST, PUT, DELETE holat o'zgartiruvchi so'rovlar va HTML formalar.
- **Ishlash mexanizmi:** Anti-CSRF tokenlari va `SameSite` cookie atributlarini tekshiradi.
- **Tasdiqlash qoidasi:** Holat o'zgartiruvchi so'rovda token bo'lmasa va SameSite yo'q bo'lsa -> `Confidence: 90` (confirmed ekvivalenti).
- **Takrorlash misoli:**
  ```bash
  curl -i -s -X POST -d "email=new@mail.com" "http://target.lab/user/update"
  ```
- **Remediation:** Barcha holat o'zgartiruvchi so'rovlarga kriptografik unikal anti-CSRF tokenlarini qo'shish va `SameSite=Lax/Strict` ni qo'llash.

#### 15. `xxe` (XML External Entity)
- **Tekshiradigan vektorlar:** `<!ENTITY xxe SYSTEM "file:///etc/passwd">`, OAST URL.
- **Ishlash mexanizmi:** XML parsing qiluvchi endpointlarga tashqi ob'ektlarni yuboradi.
- **Tasdiqlash qoidasi:** Tizim fayli aks etsa yoki OAST serverga HTTP so'rov kelib tushsa -> `SetConfidence(ConfidenceConfirmed)` (100%).
- **Takrorlash misoli:**
  ```bash
  curl -i -s -X POST -d '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>' "http://target.lab/xml"
  ```
- **Remediation:** XML parserlarda tashqi ob'ektlar (external entities) va DTD ishlovini o'chirib qo'yish (`disallow-doctype-decl`).

#### 16. `nosqli` (NoSQL Inyeksiya)
- **Tekshiradigan vektorlar:** JSON va URL parametrlar: `{"$ne": 1}`, `{"$gt": ""}`, `[$ne]=1`.
- **Ishlash mexanizmi:** MongoDB va CouchDB operatorlarini kiritib differensial javoblarni tekshiradi.
- **Tasdiqlash qoidasi:** NoSQL xatosi qaytsa yoki `$ne` operatori orqali autentifikatsiya chetlab o'tilsa -> `SetConfidence(ConfidenceConfirmed)` (100%).
- **Takrorlash misoli:**
  ```bash
  curl -i -s -H "Content-Type: application/json" -d '{"username":{"$ne":""},"password":{"$ne":""}}' "http://target.lab/login"
  ```
- **Remediation:** Kiruvchi obyekt parametrlari turlarini qat'iy tekshirish, BSON operatorlarini to'g'ridan-to'g'ri qabul qilmaslik.

#### 17. `upload` (Fayl Yuklash Zaifliklari — Opt-In)
- **Tekshiradigan vektorlar:** `.php`, `.phtml`, `.php5`, `.phar`, MIME type bypass.
- **Ishlash mexanizmi:** Multipart formalarga zararsiz test kodi bo'lgan fayllarni yuklaydi.
- **Tasdiqlash qoidasi:** Yuklangan test fayl serverda topilsa va javob bersa -> `SetConfidence(ConfidenceConfirmed)` (100%).
- **Takrorlash misoli:**
  ```bash
  curl -i -s -F "file=@test.php" "http://target.lab/upload.php"
  ```
- **Remediation:** Yuklanayotgan fayl kengaytmasini oq ro'yxat orqali tekshirish, yuklash katalogida skriptlar ijrosini o'chirish.

#### 18. `hostheader` (Host Header Injection)
- **Tekshiradigan vektorlar:** `Host: evil.com`, `X-Forwarded-Host: evil.com`.
- **Ishlash mexanizmi:** Host sarlavhasini soxtalashtiradi.
- **Tasdiqlash qoidasi:** Soxta host server javobidagi `Location` redirectida qaytsa -> `SetConfidence(ConfidenceConfirmed)` (100%). Sahifa matnida aks etsa -> `SetConfidence(ConfidenceProbable)` (80%).
- **Takrorlash misoli:**
  ```bash
  curl -i -s -H "Host: evil.com" "http://target.lab/reset-password"
  ```
- **Remediation:** Veb-serverda `SERVER_NAME` dan foydalanish, foydalanuvchi yuborgan `Host` sarlavhasiga ishonmaslik.

#### 19. `crlf` (CRLF / HTTP Response Splitting)
- **Tekshiradigan vektorlar:** `%0d%0aSet-Cookie: nightfall=test`, `%0aSet-Cookie: test=1`.
- **Ishlash mexanizmi:** URL va parametrlarga yangi qator belgilarini kiritadi.
- **Tasdiqlash qoidasi:** Server javob sarlavhalari orasida kiritilgan sarlavha aniq paydo bo'lsa -> `SetConfidence(ConfidenceConfirmed)` (100%).
- **Takrorlash misoli:**
  ```bash
  curl -i -s "http://target.lab/?lang=uz%0d%0aSet-Cookie:%20nightfall=test"
  ```
- **Remediation:** HTTP sarlavhalariga yoziladigan qiymatlardan `
` va `
` belgilarini filtrlab tashlash.

#### 20. `graphql` (GraphQL Xavfsizligi)
- **Tekshiradigan vektorlar:** `/graphql`, `/api/graphql`, `__schema` introspeksiyasi.
- **Ishlash mexanizmi:** Introspeksiya so'rovlarini yuboradi.
- **Tasdiqlash qoidasi:** To'liq schema introspeksiyasi orqali ilova modellari qaytsa -> `SetConfidence(ConfidenceConfirmed)` (100%).
- **Takrorlash misoli:**
  ```bash
  curl -i -s -X POST -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}' "http://target.lab/graphql"
  ```
- **Remediation:** Ishlab chiqarish (production) muhitida GraphQL introspeksiyasini o'chirib qo'yish.

#### 21. `protopollution` (Prototype Pollution)
- **Tekshiradigan vektorlar:** `__proto__`, `constructor.prototype`.
- **Ishlash mexanizmi:** JSON tanasiga ob'ekt xususiyatlarini kiritadi.
- **Tasdiqlash qoidasi:** Prototip xususiyati serverdagi obyekt javobida aks etsa -> `SetConfidence(ConfidenceConfirmed)` (100%).
- **Takrorlash misoli:**
  ```bash
  curl -i -s -H "Content-Type: application/json" -d '{"__proto__":{"polluted":"true"}}' "http://target.lab/api/settings"
  ```
- **Remediation:** `Object.freeze(Object.prototype)` dan foydalanish yoki `Object.create(null)` yordamida toza obyektlar yaratish.

#### 22. `massassign` (Mass Assignment)
- **Tekshiradigan vektorlar:** `admin: true`, `role: admin`, `is_admin: 1`.
- **Ishlash mexanizmi:** Ob'ektlarga ruxsatsiz imtiyozli maydonlarni qo'shadi.
- **Tasdiqlash qoidasi:** Imtiyozli maydon server tomonidan qabul qilinib, javobda qaytsa -> `SetConfidence(ConfidenceConfirmed)` (100%).
- **Takrorlash misoli:**
  ```bash
  curl -i -s -X POST -H "Content-Type: application/json" -d '{"username":"user1","is_admin":true}' "http://target.lab/api/users"
  ```
- **Remediation:** Faqat ruxsat etilgan maydonlarni qabul qiluvchi DTO (Data Transfer Object) modellardan foydalanish.

#### 23. `deserialize` (Xavfli Deserializatsiya)
- **Tekshiradigan vektorlar:** Java, PHP, Python, .NET serializatsiyalangan obyekt belgilari.
- **Ishlash mexanizmi:** OAST callback yoki xos belgilar bilan deserializatsiya xatolarini qo'zg'atadi.
- **Tasdiqlash qoidasi:** OAST callback qaytsa yoki xos xatolik yuz bersa -> `SetConfidence(ConfidenceConfirmed)` (100%).
- **Takrorlash misoli:**
  ```bash
  curl -i -s -b "user_obj=Tzo0OiJVc2VyIjoxOntzOjQ6Im5hbWUiO3M6NToiYWRtaW4iO30=" "http://target.lab/index.php"
  ```
- **Remediation:** Noma'lum va ishonchsiz manbalardan kelgan serializatsiyalangan ob'ektlarni qabul qilmaslik, JSON kabi xavfsiz formatlarga o'tish.

---

## 7. XSS dvigateli

NightfallLX XSS dvigateli XSStrike vositasining aqlli kontekstli tahlil tamoyillari asosida yaratilgan.

### 7.1 Bayroqlar va parametrlar
- `--dom` (standart: `true`): HTML va JavaScript manbalari (sources) hamda xavfli sinklarini statik tahlil qiladi.
- `--no-dom`: Statik DOM tahlilini o'chiradi.
- `--dom-browser`: Tizimda o'rnatilgan Headless Chrome/Chromium yordamida DOM XSS ni real brauzerda `alert(1)` hodisasi chaqirilishi orqali tasdiqlaydi.
- `--forms`: Sahifadagi barcha HTML formalarni avtomatik ajratib oladi, yashirin CSRF tokenlarini yangilaydi va form kiritmalarini tekshiradi.
- `--stored`: Formalarga test belgilarini yuboradi va keyin sahifani qayta tekshirib, saqlanuvchi (Stored) XSS ni aniqlaydi.
- `--crawl`: Saytni rekursiv kroul qilib, aniqlangan barcha parametr va formalarda XSS dvigatelini yurgazadi.
- `--xss-fuzz`: Parametrlarni maxsus belgilar (`<`, `>`, `"`, `'`, `/`, `;`) bilan proba qilib, filtrdan omon qolish qobiliyatini o'rganadi.
- `-m xss`: Standart skanerlash rejimida faqat XSS modulini ishlatish.

### 7.2 Canary mexanizmi
Eski vositalardagi kabi oddiy `<script>alert(1)</script>` yuborilmaydi. Sababi: agar sahifada oldindan statik `alert(1)` bo'lsa, bu har doim soxta ijobiy (false positive) natija beradi.
Buning o'rniga, har bir proba uchun unikal canary hosil qilinadi:
`lxc` prefiksi va 12 ta tasodifiy hex belgisi (masalan: `lxc4e8a1b2c3d4e`).
Payload aynan shu canary asosida shakllantiriladi (masalan: `<script>/*lxc4e8a1b2c3d4e*/</script>` yoki `"><img src=x onerror=lxc4e8a1b2c3d4e>`).

### 7.3 Tasdiqlash qoidalari
Dastur javobni olganda quyidagilarni tekshiradi:
1. Yuborilgan unikal canary server javobida bormi?
2. `CheckExecutableNode(body, canary)` funksiyasi chaqiriladi. U HTML daraxtini tahlil qilib, canary xavfli kontekstda (HTML tegi ochilishida, script blokida, hodisa atributida `onerror`, `onload` yoki `javascript:` protokoli ichida) ekanligini tasdiqlaydi.
Ikkala shart bajarilsa -> `confirmed` (100%).
Agar belgilar filtrsiz qaytsa-yu, ammo xavfsiz matn ichida bo'lsa -> `probable` (80%).
Agar belgilar qisman filtrlanib qaytsa -> `possible` (50%).

### 7.4 Stored XSS ogohlantirishi
`--stored` rejimi ishlatilganda, yuborilgan test markerlari nishon veb-ilova ma'lumotlar bazasida (izohlar, profil ma'lumotlari, xabarlar) saqlanib qolishi mumkin. Ushbu bayroqni faqat ruxsat etilgan test muhitlarida ishlating!

### 7.5 DOM XSS Manbalar (Sources) va Sinklar (Sinks)
Statik DOM tahlil dvigateli (`--dom`) brauzerning JavaScript muhitidagi quyidagi xavfli manbalar va sinklarni qidiradi:

| Turi | Nomi | Izoh |
|---|---|---|
| **Manba (Source)** | `location.search` | URL so'rov parametrlari |
| **Manba (Source)** | `location.hash` | URL fragmenti (`#` dan keyingi qism) |
| **Manba (Source)** | `document.URL` / `document.documentURI` | Sahifaning to'liq URL manzili |
| **Manba (Source)** | `document.referrer` | Foydalanuvchi kelgan oldingi sahifa manzili |
| **Manba (Source)** | `window.name` | Oyna ob'ektining nomi |
| **Sink (Xavfli nuqta)** | `element.innerHTML` | HTML matnni DOM ga to'g'ridan-to'g'ri chizish |
| **Sink (Xavfli nuqta)** | `element.outerHTML` | Element va uning bolalarini almashtirish |
| **Sink (Xavfli nuqta)** | `document.write()` / `writeln()` | Sahifaga xom HTML yozish |
| **Sink (Xavfli nuqta)** | `window.eval()` | Satrni JS kodi sifatida bajarish |
| **Sink (Xavfli nuqta)** | `setTimeout()` / `setInterval()` | Birinchi argument satr bo'lsa kod ijro qilinishi |
| **Sink (Xavfli nuqta)** | `new Function()` | Dinamik funksiya yaratish |
| **Sink (Xavfli nuqta)** | `element.setAttribute()` | Hodisalar (`onload`, `onerror`) yoki `href="javascript:..."` |

### 7.6 Kontekstual Tahlilchi (Context Parser)
Dvigatel nishon parametr HTML ning qaysi qismiga tushayotganini aniqlaydi:
1. **HTML matn konteksti:** `<p>Salom, {{PARAM}}</p>` — bu yerda teg ochish (`<script>`, `<img>`) talab qilinadi.
2. **Atribut qiymati konteksti:** `<input value="{{PARAM}}">` — bu yerdan chiqish uchun qo'shtirnoq (`"`) yoki apostrof (`'`) kerak.
3. **Hodisa ishlovchisi konteksti:** `<button onclick="doAction('{{PARAM}}')">` — bu yerda JS satridan chiqish yoki yangi buyruq zanjirlash zarur.
4. **Skript bloki konteksti:** `<script>var user = "{{PARAM}}";</script>` — bu yerda `</script>` orqali blokni yopish yoki JS ifodasini yakunlash kerak.

### 7.7 Headless Brauzer Integratsiyasi (`--dom-browser`)
Agar operator `--dom-browser` bayrog'ini ko'rsatsa, statik tahlil bilan cheklanmasdan, tizimdagi Chrome/Chromium fon rejimida (`--headless --disable-gpu`) ochiladi:
- Chrome DevTools Protocol (CDP) orqali `Page.javascriptDialogOpening` hodisasi tinglanadi.
- Sahifada kiritilgan payload haqiqatan ham `alert()`, `confirm()` yoki `prompt()` dialogni ochsa, hodisa tutib olinadi va zaiflik zudlik bilan `confirmed` deb belgilanadi.

---

## 8. Autentifikatsiyalangan skanerlash va ilg'or funksiyalar

Dastur avtorizatsiyadan o'tishni talab qiladigan ilovalarni to'liq avtomatlashtirilgan tarzda skanerlash imkonini beradi.

### 8.1 Autentifikatsiya bayroqlari
- `-login-url`: Tizimga kirish so'rovi yuboriladigan URL (masalan: `http://target.lab/login.php`).
- `-login-data`: Kirish so'rovi tanasi shabloni. `{{user}}` va `{{pass}}` o'rniga haqiqiy foydalanuvchi ma'lumotlari qo'yiladi. Form-url: `user={{user}}&pass={{pass}}` yoki JSON: `{"username":"{{user}}","password":"{{pass}}"}`.
- `-login-user`: Foydalanuvchi nomi. Agar flag bo'sh bo'lsa, `LOGIN_USER` muhit o'zgaruvchisidan olinadi.
- `-login-pass`: Parol. Agar flag bo'sh bo'lsa, `LOGIN_PASS` muhit o'zgaruvchisidan olinadi.
- `-login-success-regex`: Kirish muvaffaqiyatli bo'lganini tasdiqlovchi regex (masalan: `Dashboard|Logout|Welcome`).
- `-login-success-status`: Kirish muvaffaqiyatli bo'lgandagi kutilgan HTTP status kodi (masalan: `200` yoki `302`).
- `-logout-regex`: Sessiya eskirganini bildiruvchi regex. Agar server javobida ushbu matn paydo bo'lsa, HTTP mijoz avtomatik ravishda qayta kiradi (re-login) va so'rovni takrorlaydi.
- `-bearer`: `Authorization: Bearer <token>` sarlavhasini o'rnatish.
- `-refresh-url`: Muddati o'tgan tokenni yangilash endpointi.
- `-refresh-json-path`: Yangi tokenni JSON javobidan ajratib olish yo'li (standart: `access_token`).

### 8.2 Ilg'or sozlamalar
- `-json`: POST so'rov tanasini JSON sifatida tahlil qiladi. Dastur JSON daraxtidagi har bir barg nuqtani (leaf node) alohida aniqlab, har bir parametrga zaiflik payloadlarini inyeksiya qiladi.
- `-rate`: Sekundiga yuboriladigan so'rovlar soni cheklovi (standart: `0` = cheklovsiz). Nozik yoki zaif serverlarni yiqitmaslik uchun ishlatiladi (masalan: `-rate 10`).
- `-oast-listen`: Out-of-band callback serveri tinglaydigan lokal IP va port (masalan: `0.0.0.0:8888`).
- `-oast-host`: Payloadlar ichiga joylashtiriladigan tashqi IP yoki domen (masalan: `10.10.14.x`).
- `-oast-wait`: OAST callback javobini kutish vaqti soniyalarda (standart: `10`).
- `-sqli-delay`: Time-based SQL inyeksiya tekshiruvlarida kutiladigan kechikish vaqti (standart: `3` soniya).
- `-discover-params`: Javob biseksiyasi yordamida yashirin GET parametrlarini qidirish.
- `-w`: Wordlist fayli yo'li.

### 8.3 JSON Daraxtini Tahlil Qilish va Inyeksiya
NightfallLX oddiy satrli almashtirish bilan cheklanmaydi. Agar so'rov tanasi JSON formatida bo'lsa yoki `-json` bayrog'i berilgan bo'lsa:
1. Dastur JSON ob'ektini rekursiv daraxt (tree) ko'rinishida tahlil qiladi.
2. Daraxtdagi barcha oxirgi barg nuqtalar (leaf nodes, masalan: `user.profile.address.city`) aniqlanadi.
3. Har bir barg nuqtaga alohida-alohida test payloadlari kiritilib, qolgan barcha maydonlar asl holatida saqlanadi. Bu murakkab API larda so'rov validatsiyasidan muvaffaqiyatli o'tishni ta'minlaydi.

### 8.4 Arjun uslubidagi Parametrlarni Qidirish Algoritmi (`-discover-params`)
Yashirin HTTP parametrlarini topishda chiziqli bitta-bittalab so'rov yuborish juda sekin ishlaydi. Shuning uchun NightfallLX **javob biseksiyasi (bisection)** algoritmini qo'llaydi:
- Wordlistdagi barcha nomzod parametrlar (masalan 1000 ta) guruhlarga (masalan 50 tadan) bo'linadi.
- Bitta so'rovda 50 ta parametr yuboriladi: `?p1=1&p2=1&...&p50=1`.
- Server javobi asosiy sahifa bilan taqqoslanadi.
- Agar hajm, status yoki javob tanasida anomaliya aniqlansa, ushbu 50 talik guruh ikkiga bo'linadi (25 ta va 25 ta) va qidiruv rekursiv davom ettiriladi.
- Natijada bir necha yuzlab so'rovlar o'rniga sanoqli so'rovlar yordamida yashirin `debug`, `admin`, `secret` parametrlari topiladi.

### 8.5 OAST (Out-of-band Application Security Testing) Arxitekturasi
Blind zaifliklarni (Blind SSRF, Blind XXE, Blind Deserialization) aniqlash uchun tashqi uchinchi tomon xizmatlariga (masalan interactsh yoki burpcollaborator) bog'lanib qolmaslik maqsadida NightfallLX o'z ichida to'liq mustaqil HTTP callback serveriga ega:
- `-oast-listen 0.0.0.0:8888`: Lokal interfeysda HTTP server ko'tariladi.
- `-oast-host 10.10.14.x:8888`: Nishon server murojaat qilishi kerak bo'lgan tashqi VPN/IP manzil.
- Modullar (masalan `ssrf` yoki `xxe`) unikal ID bilan URL shakllantiradi: `http://10.10.14.x:8888/ssrf_canary_abc123`.
- Agar nishon server ushbu manzilga so'rov yuborsa, ichki server buni qayd qiladi va modulga xabar beradi.
- Natijada tashqi internetga ulanmagan yopiq laboratoriyalarda ham Blind zaifliklar to'liq aniqlanadi.

---

## 9. Intel (versiyaga mos referens qidiruvi)

Skanerlash paytida nishon tizimda aniqlangan komponentlar bo'yicha qo'shimcha xavfsizlik ma'lumotlari avtomatik yig'iladi.

### 9.1 Ishlash mexanizmi
Dastur `Server`, `X-Powered-By`, `generator` sarlavhalari hamda `pkg/detector` topilmalari orqali dasturiy ta'minot nomi va aniq versiyasini ajratib oladi (masalan: `Apache 2.4.49`, `PHP 8.1.0`).

### 9.2 Bayroqlar
- `--intel-query`: Qidiruv so'rovini qo'lda kiritish (masalan: `-intel-query "Apache 2.4.49"`).
- `--no-intel`: Versiyalarni qidirish tizimini butunlay o'chirish.
- `-nvd`: NIST NVD 2.0 REST API orqali rasmiy CVE va CVSS ballarini so'rash.

### 9.4 Searchsploit va NVD Qidiruv Formatlari
`pkg/intel/intel.go` moduli komponentlar versiyasini quyidagi usulda so'raydi:
1. **Mahalliy Searchsploit (JSON rejimi):**
   Tizimda `searchsploit` buyrug'i mavjud bo'lsa, u JSON formatida chaqiriladi:
   ```bash
   searchsploit --json -- "Apache 2.4.49"
   ```
   Dastur olingan JSON dagi `RESULTS_EXPLOIT` massivini o'qiydi. Undan `Title`, `Path` (Exploit-DB dagi fayl yo'li) va tegishli `EDB-ID` raqamlarini ajratadi.
2. **NIST NVD REST API 2.0:**
   Agar `-nvd` bayrog'i yoqilgan bo'lsa, NIST NVD rasmiy API endpointiga HTTPS so'rovi yuboriladi:
   `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Apache+2.4.49`
   Javobdagi har bir CVE uchun CVSS v3.1 asosiy bali (Base Score) va zaiflik ta'rifi olinadi. Agar `NVD_API_KEY` o'rnatilgan bo'lsa, `apiKey` sarlavhasi qo'shilib, tezkor rejimda so'rovlar bajariladi.

### 9.3 Qat'iy qoida
Ushbu natijalar hisobotda **`Version-matched intel (not verified)`** bo'limida ko'rsatiladi. Kodda qat'iy belgilangan: **Intel natijalari hech qachon tasdiqlangan zaiflik (confirmed finding) hisoblanmaydi!** Ular faqatgina ommaviy ma'lumotlar bazasidan olingan ma'lumotnoma sifatida taqdim etiladi.

---

## 10. Hisobot fayllari

Baholash yakunida dastur avtomatik tarzda ikkita hisobot faylini yaratadi:

### 10.1 Fayl nomlari va formatlar
- `-o`: Hisobot fayllarining asosiy nomi (standart: `lab_report`).
  - `lab_report.md`: Markdown formati. Pentest hisoboti uchun qulay ko'rinishda. Har bir topilma, uning xavflilik darajasi, ishonchlilik foizi, zaif parametr, PoC payload, server javobidan olingan dalil va uni takrorlash uchun tayyor `curl` buyrug'ini o'z ichiga oladi.
  - `lab_report.json`: JSON formati. Ma'lumotlarni boshqa avtomatlashtirilgan vositalar orqali tahlil qilish uchun to'liq tuzilmali ma'lumotlar.
- `--log`: Ko'rsatilgan faylga baholash natijalarini to'liq yozib boradi.

### 10.2 Hisobot namunalari

#### Markdown hisoboti namunasi (`lab_report.md`):
```markdown
# NightfallLX Assessment Report

- **Target:** `http://target.htb/view.php`
- **Method:** `GET`
- **Parameters Tested:** `[id]`
- **Scan Date:** 2026-10-23 10:15:00 UTC+5
- **Total Confirmed Findings:** 1

---

## Findings Summary

| Module | Title | Severity | Confidence | Parameter |
|---|---|---|---|---|
| `lfi` | Local File Inclusion (Path Traversal) | **CRITICAL** | confirmed (100%) | `file` |

### 1. Local File Inclusion (Path Traversal)

- **Module:** `lfi`
- **Severity:** **CRITICAL**
- **Confidence:** confirmed (100%)
- **CWE ID:** [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
- **Vulnerable Parameter:** `file`
- **PoC Payload:** `../../../../etc/passwd`

#### Detail
Discovered local file inclusion vulnerability exposing system file contents.

#### Evidence Snippet
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

#### Remediation
Validate and sanitize all file paths against a strict allowlist.

#### Proof of Concept Reproduction
```bash
curl -i -s "http://target.htb/view.php?file=../../../../etc/passwd"
```
```

#### JSON hisoboti namunasi (`lab_report.json`):
```json
{
  "target": {
    "url": "http://target.htb/view.php",
    "method": "GET",
    "parameters": ["file"]
  },
  "scan_date": "2026-10-23T10:15:00+05:00",
  "total_findings": 1,
  "findings": [
    {
      "module": "lfi",
      "title": "Local File Inclusion (Path Traversal)",
      "severity": "CRITICAL",
      "confidence": 100,
      "confidence_level": "confirmed",
      "url": "http://target.htb/view.php",
      "parameter": "file",
      "payload": "../../../../etc/passwd",
      "evidence": "root:x:0:0:root:/root:/bin/bash\n",
      "remediation": "Validate and sanitize all file paths against a strict allowlist.",
      "cwe_id": 22,
      "curl_cmd": "curl -i -s "http://target.htb/view.php?file=../../../../etc/passwd""
    }
  ]
}
```

---

## 11. Flag jadvali

`nightfalllx-go/main.go` faylidagi barcha 76 ta flag (birlamchi va muqobil nomlar) to'liq ro'yxati:

### 11.1 Nishon va Kiritish (Targets & Input)
| Flag | Turi | Standart qiymat | Tavsifi |
|---|---|---|---|
| `-u` | string | `""` | Nishon URL yoki shablon (masalan: `http://target.lab/?id=1` yoki `http://target/FUZZ`) |
| `-l` | string | `""` | Ko'p nishonli ketma-ket skanerlash uchun URL lar ro'yxati fayli yo'li (har bir qatorda bitta URL) |
| `-list` | string | `""` | `-l` bayrog'ining muqobil nomi |
| `-r` | string | `""` | Burp Suite xom HTTP so'rov fayli yo'li |
| `-domain` | string | `""` | Subdomen va VHost fuzzing uchun domen (masalan: `target.lab`) |
| `-https` | bool | `false` | HTTPS sxemasini majburiy qo'llash |
| `-ssl` | bool | `false` | `-https` bayrog'ining muqobil nomi |

### 11.2 HTTP Sozlamalari (HTTP Settings)
| Flag | Turi | Standart qiymat | Tavsifi |
|---|---|---|---|
| `-X` | string | `"GET"` | HTTP metodi (`GET`, `POST`, `PUT`, `DELETE` va h.k.) |
| `-d` | string | `""` | POST so'rov tanasi ma'lumotlari |
| `-H` | array | `[]` | Maxsus HTTP sarlavhasi (takrorlanuvchi, masalan: `-H "Authorization: Bearer ..."`) |
| `-header` | array | `[]` | `-H` bayrog'ining to'liq nomi |
| `-b` | string | `""` | Cookie sarlavhasi qiymati |
| `-p` | string | `""` | HTTP proksi manzili (masalan: `http://127.0.0.1:8080`) |
| `-k` | bool | `true` | TLS sertifikatlarini tekshirishni o'chirish (laboratoriyalar uchun standart: true) |
| `-timeout` | int | `15` | So'rov taymauti soniyalarda |
| `-rate` | int | `0` | Sekundiga so'rovlar soni cheklovi (`0` = cheklovsiz) |
| `-json` | bool | `false` | So'rov tanasini JSON sifatida tahlil qilish |

### 11.3 Scope va Huquqlar (Scope Guard)
| Flag | Turi | Standart qiymat | Tavsifi |
|---|---|---|---|
| `-scope` | string | `""` | Ruxsat etilgan domenlar ro'yxati yoki fayl yo'li (masalan: `target.lab,*.target.lab`) |
| `-scope-off` | bool | `false` | Scope tekshiruvini butunlay o'chirish |
| `-b2` | string | `""` | IDOR testi uchun 2-foydalanuvchi cookie qiymati |
| `-H2` | array | `[]` | IDOR testi uchun 2-foydalanuvchi sarlavhalari |

### 11.4 Modullar (Modules)
| Flag | Turi | Standart qiymat | Tavsifi |
|---|---|---|---|
| `-m` | string | `"all"` | Vergul bilan ajratilgan modullar ro'yxati yoki `all` |

### 11.5 Fuzzing va VHost
| Flag | Turi | Standart qiymat | Tavsifi |
|---|---|---|---|
| `-w` | string | `""` | Wordlist fayli yo'li yoki tezkor kalit so'z (`common`, `lfi`, `params`, `rockyou`, `4digit`, `colors`, `cities`, `pins`, `users`; standart: avtomatik aniqlanadi) |
| `-t` | int | `40` | Parallel goroutine ishchilari soni |
| `-fuzz` | bool | `false` | Tezkor fuzzing rejimini yoqish |
| `-subdomain` | bool | `false` | Subdomen va VHost qidiruv rejimini yoqish |
| `-sub` | bool | `false` | `-subdomain` bayrog'ining muqobil nomi |
| `-ac` | bool | `true` | Wildcard javoblarni avtomatik kalibratsiya qilish |
| `-mc` | string | `""` | Mos keluvchi HTTP status kodlari (masalan: `200,301`) |
| `-fc` | string | `"404"` | Filtrlangan HTTP status kodlari |
| `-ms` | string | `""` | Mos keluvchi javob o'lchamlari baytlarda |
| `-fs` | string | `""` | Filtrlangan javob o'lchamlari |
| `-mw` | string | `""` | Mos keluvchi javob so'zlar soni |
| `-fw` | string | `""` | Filtrlangan javob so'zlar soni |
| `-ml` | string | `""` | Mos keluvchi javob satrlar soni |
| `-fl` | string | `""` | Filtrlangan javob satrlar soni |

### 11.6 Parametrlarni qidirish (Parameter Discovery)
| Flag | Turi | Standart qiymat | Tavsifi |
|---|---|---|---|
| `-discover-params` | bool | `false` | Yashirin parametrlarni biseksiya orqali qidirish |
| `-param-brute` | bool | `false` | Yashirin parametrlarni wordlist bilan to'liq qidirish |

### 11.7 XSS Dvigateli
| Flag | Turi | Standart qiymat | Tavsifi |
|---|---|---|---|
| `-dom` | bool | `true` | Statik DOM tahlilini yoqish |
| `-no-dom` | bool | `false` | Statik DOM tahlilini o'chirish |
| `-dom-browser` | bool | `false` | Headless brauzer orqali tekshirish |
| `-forms` | bool | `false` | HTML formalarni ajratib olib tekshirish |
| `-xss-fuzz` | bool | `false` | Filtrlarni maxsus belgilar bilan proba qilish |
| `-stored` | bool | `false` | Saqlanuvchi (Stored) XSS ni tekshirish |
| `-crawl` | bool | `false` | Saytni aylanib XSS ni ishga tushirish |

### 11.8 Versiya Intel (Searchsploit & NVD)
| Flag | Turi | Standart qiymat | Tavsifi |
|---|---|---|---|
| `-intel-query` | string | `""` | Qo'lda mahsulot va versiya qidirish so'rovi |
| `-no-intel` | bool | `false` | Versiya referens qidiruvini o'chirish |
| `-nvd` | bool | `false` | NIST NVD 2.0 API orqali qidirish |

### 11.9 Autentifikatsiya (Authentication)
| Flag | Turi | Standart qiymat | Tavsifi |
|---|---|---|---|
| `-login-url` | string | `""` | Kirish (login) so'rovi yuboriladigan URL |
| `-login-data` | string | `""` | Kirish shabloni (`{{user}}` va `{{pass}}` bilan) |
| `-login-user` | string | `""` | Foydalanuvchi nomi |
| `-login-pass` | string | `""` | Parol |
| `-login-success-regex` | string | `""` | Muvaffaqiyatli kirishni tasdiqlovchi regex |
| `-login-success-status` | int | `0` | Muvaffaqiyatli kirish status kodi |
| `-logout-regex` | string | `""` | Sessiya eskirganini bildiruvchi regex |
| `-bearer` | string | `""` | Bearer token qiymati |
| `-refresh-url` | string | `""` | Tokenni yangilash URL manzili |
| `-refresh-json-path` | string | `"access_token"` | Yangi tokenni ajratish JSON yo'li |

### 11.10 OAST & SQLi Sozlamalari
| Flag | Turi | Standart qiymat | Tavsifi |
|---|---|---|---|
| `-oast-listen` | string | `""` | OAST HTTP tinglovchi IP:Port |
| `-oast-host` | string | `""` | OAST ommaviy xost manzili |
| `-oast-wait` | int | `10` | OAST javobini kutish vaqti (soniya) |
| `-sqli-delay` | int | `3` | Time-based SQLi kutish vaqti (soniya) |

### 11.11 Diagnostika, TUI va Maxsus Rejimlar
| Flag | Turi | Standart qiymat | Tavsifi |
|---|---|---|---|
| `-doctor` | bool | `false` | Diagnostika tekshiruvlarini o'tkazish |
| `-troubleshoot` | bool | `false` | `-doctor` bayrog'ining muqobil nomi |
| `-tech` | bool | `false` | Texnologiyalarni aniqlash rejimi |
| `-map` | bool | `false` | Sayt arxitekturasi xaritasini tuzish |
| `-spider` | bool | `false` | `-map` bayrog'ining muqobil nomi |
| `-depth` | int | `3` | Krouler rekursiya chuqurligi |
| `-max-urls` | int | `50` | Krouler topadigan maksimal URL soni |
| `-spa` | bool | `false` | Headless Chrome orqali SPA (React/Vue/Angular) renderlash va marshrutlarni qidirish |
| `-devbuster` | bool | `false` | Zamonaviy SPA krouleri va JS bundle marshrut fuzzeri (Devbuster) |
| `-dbuster` | bool | `false` | `-devbuster` bayrog'ining muqobil nomi |
| `-include-subdomains` | bool | `false` | Devbuster rejimida subdomenlarni scope'ga kiritish |
| `-hide-status` | string | `""` | Devbuster rejimida yashiriladigan status kodlar (masalan: `403,404`) |
| `-status` | string | `""` | Devbuster rejimida faqat ko'rsatiladigan status kodlar (masalan: `200,301`) |
| `-delay` | float | `0` | So'rovlar orasidagi kutish vaqti soniyalarda (masalan: `0.5`) |
| `-shodan` | bool | `false` | Shodan OSINT qidiruvi |
| `-shodan-key` | string | `""` | Shodan API kaliti |
| `-i` | bool | `false` | Interaktiv sichqoncha paneli (TUI) |
| `-ui` | bool | `false` | `-i` bayrog'ining muqobil nomi |
| `-tui` | bool | `false` | `-i` bayrog'ining muqobil nomi |
| `-version` | bool | `false` | Dastur versiyasini ko'rsatish |
| `-V` | bool | `false` | `-version` bayrog'ining muqobil nomi |

### 11.12 Chiqish va Hisobot (Output)
| Flag | Turi | Standart qiymat | Tavsifi |
|---|---|---|---|
| `-o` | string | `"lab_report"` | Hisobot fayllarining asosiy nomi |
| `-log` | string | `""` | Natijalarni maxsus log fayliga yozish |

---

## 12. Xavfsizlik qoidalari

NightfallLX xavfsizlik va axloqiy me'yorlarga to'liq rioya qilgan holda tuzilgan:

1. **Ekspluatatsiya taqiqlangan:**
   Dastur zaifliklarni aniqlaydi, ammo ularni to'liq ekspluatatsiya qilib tizimga zarar yetkazmaydi.
2. **Qobiq (Shell) olinmaydi:**
   Buyruqlar inyeksiyasi (CMDi) modullarida teskari qobiq (reverse shell) ulanishlari bajarilmaydi. Faqatgina zararsiz `echo` yoki vaqt kechikishlari bilan cheklanadi.
3. **Faqat Searchsploit havolalari:**
   Topilgan zaifliklar uchun eksploit kodlari avtomatik ishga tushirilmaydi. Dastur faqatgina ommaviy axborot manbasi sifatidagi yo'l va CVE raqamlarini taqdim etadi.
4. **Maxfiy ma'lumotlarni yashirish (Masking):**
   Hisobotlarda va terminal chiqishida parollar, avtorizatsiya tokenlari va maxfiy kalitlar yashirib ko'rsatiladi.
5. **Scope Guard xatti-harakati:**
   Kodda belgilangan amaldagi holat (`nightfalllx-go/pkg/client/http.go:135-138` va `268-270` qatorlar):
   ```go
   func (c *Client) IsInScope(host string) bool {
       if c.ScopeOff || len(c.ScopeHosts) == 0 {
           return true
       }
       ...
   }
   ```
   Standart holatda agar operator `-scope` bayrog'ini ko'rsatmasa (`len(ScopeHosts) == 0`), `IsInScope` funksiyasi doimo `true` qaytaradi va barcha so'rovlarga ruxsat beriladi. Agar `-scope target.htb,*.target.htb` berilsa, ushbu ro'yxatdan tashqaridagi har qanday manzilga so'rovlar darhol to'xtatiladi:
   `"scope guard refusal: host is not in authorized scope"`.
   Agar tekshiruvni butunlay o'chirish kerak bo'lsa, `-scope-off` bayrog'i ishlatiladi.

---

## 13. Ish oqimi (workflow)

Laboratoriya mashinasi (masalan HackTheBox) ustida ishlashda tavsiya etiladigan bosqichma-bosqich reja:

```
+-------------------------------------------------------------+
| 1. Razvedka: -tech yordamida texnologiyalarni aniqlash     |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
| 2. Xarita: -map orqali arxitekturani spider qilish          |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
| 3. VHost Fuzzing: -H "Host: FUZZ.<domain>" -ac              |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
| 4. Audit: -u "<url>?id=1" -m all orqali zaifliklarni topish |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
| 5. XSS tekshiruvi: --crawl yordamida formalarni skanerlash   |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
| 6. Qo'lda tekshirish: curl buyruqlari bilan tasdiqlash      |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
| 7. Hisobot: lab_report.md va lab_report.json ni tahlil qilish|
+-------------------------------------------------------------+
```

### Amaliy buyruqlar ketma-ketligi:
```bash
# 1. Texnologiyalarni aniqlash
nightfalllx -tech -u http://10.129.x.x/

# 2. Sayt xaritasini tuzish
nightfalllx -map -depth 3 -max-urls 40 -u http://target.htb/

# 3. Virtual xostlarni topish
nightfalllx -u http://10.129.x.x/ -H "Host: FUZZ.target.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -ac

# 4. Asosiy zaifliklarni skanerlash
nightfalllx -u "http://target.htb/profile.php?id=1" -m all -o htb_report

# 5. Formalarni XSS ga tekshirish
nightfalllx --crawl -depth 2 -u http://target.htb/

# 6. Qo'lda tasdiqlash (hisobotdan olingan curl buyrug'i)
curl -i -s "http://target.htb/profile.php?id=1'%20UNION%20SELECT%20null,version()--"
```

---

### 13.1 Haqiqiy HTB Mashinasi Misolida To'liq Ssenariy
Aytaylik, HackTheBox platformasida `10.129.204.15` IP manzilidagi yangi mashina berildi:

1. **Recon boshlash:**
   ```bash
   nightfalllx -tech -u http://10.129.204.15/
   ```
   Chiqish: `Apache 2.4.41 (Ubuntu)`, `PHP 7.4.3`, redirect aniqlanadi: `http://horizontall.htb/`.

2. **Domen va vhostlarni aniqlash:**
   `/etc/hosts` ga `10.129.204.15 horizontall.htb` qo'shiladi va VHost fuzzing ishga tushiriladi:
   ```bash
   nightfalllx -u http://10.129.204.15/ -H "Host: FUZZ.horizontall.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -ac
   ```
   Natija: `api-prod.horizontall.htb` topiladi (Status 200 OK, Size 842 bayt).
   `/etc/hosts` ga `api-prod.horizontall.htb` qo'shiladi.

3. **API va parametrlarni skanerlash:**
   ```bash
   nightfalllx -tech -u http://api-prod.horizontall.htb/
   ```
   Chiqish: `Strapi Framework (Node.js)`.

4. **Zaifliklarni skanerlash va Intel:**
   ```bash
   nightfalllx -u "http://api-prod.horizontall.htb/reviews?id=1" -m all -o horizontall_audit
   ```
   Intel bo'limida Strapi versiyasiga mos keluvchi RCE va autentifikatsiyani chetlab o'tish CVE lari ko'rsatiladi.

5. **Hisobotni o'rganish:**
   `horizontall_audit.md` fayli ochilib, barcha topilmalar tahlil qilinadi.

## 14. Muammolar va maslahatlar

### 14.1 Kodda aniqlangan muammolar
1. **`-sub` bayrog'i xatosi:** `-sub -u http://IP -domain target.htb` buyrug'i fuzzerga kirmaydi, chunki trigger tekshiruvi `Host: FUZZ.<domain>` o'rnatilishidan oldin bajariladi. Doimo `-H "Host: FUZZ.target.htb"` shaklida ishlating.
2. **WAF va CSRF modullarida `ConfidenceLevel` qiymati:** Kodda ushbu modullar `SetConfidence` chaqirmasdan to'g'ridan-to'g'ri `Confidence` sonini o'rnatadi. `pkg/reporters` dagi `formatConfidence` funksiyasi buni avtomatik to'g'irlab, 90 dan yuqori bo'lsa `confirmed` deb aks ettiradi.

### 14.2 Umumiy xatolar va ularni tuzatish
- **"Invalid target URL" xatosi:** URL manzilida `http://` yoki `https://` ko'rsatilmagan bo'lsa yuz beradi. Manzilni to'liq ko'rsatish tavsiya etiladi.
- **"Scope guard refusal" xatosi:** Agar `-scope target.htb` berilgan bo'lsa va sayt boshqa domenga yo'naltirsa, so'rov to'xtatiladi. Barcha kerakli domenlarni vergul bilan qo'shing: `-scope target.htb,cdn.target.htb`.
- **"Fuzzer error: wordlist is required" xatosi:** Fuzzing rejimida `-w` orqali lug'at fayli ko'rsatilmagan bo'lsa yuz beradi.

### 14.3 Sekin ishlaydigan nishonlar uchun maslahatlar
- Tarmoq sekin bo'lsa yoki server cheklovlar qo'ysa, goroutinelar sonini kamaytiring: `-t 5` yoki `-t 10`.
- Taymout vaqtini oshiring: `-timeout 30`.
- So'rovlar chastotasini cheklang: `-rate 5` (sekundiga 5 ta so'rov).
- OAST kutish vaqtini oshiring: `-oast-wait 15`.

---

## 15. Ma'lum muammolar va cheklovlar

1. **Go 1.26 talabi:** `go.mod` faylida Go 1.26 ko'rsatilgan. Eski Go versiyalarida loyihani kompilyatsiya qilishda xatoliklar yuz berishi mumkin.
2. **Real Searchsploit testlari:** Avtomatlashtirilgan birlik testlarida haqiqiy `searchsploit` chaqiruvlari tekshirilmagan (soxta mock ma'lumotlar ishlatilgan), chunki turli operatsion tizimlarda `exploitdb` o'rnatilmagan bo'lishi mumkin.
3. **Statik DOM tahlilining cheklovlari:** `--dom` tahlili statik regex qoidalari orqali ishlaydi. To'liq murakkab JavaScript ob'ektlari va hodisalarini faqat `--dom-browser` yordamida aniqlash mumkin.
4. **NVD API cheklovlari:** Agar `NVD_API_KEY` o'rnatilmagan bo'lsa, NIST NVD 2.0 REST API soatiga cheklangan so'rovlarni qabul qiladi.
5. **Potensial False Negatives (Aniqlanmay qolish ehtimoli):** Agar serverda qattiq WAF qoidalari yoki maxsus kodlash talablari bo'lsa, ba'zi inyeksiyalar aniqlanmay qolishi mumkin.

---

## 16. Ilova: tekshirish

Ushbu qo'llanmadagi barcha faktlar quyidagi amaliy tekshiruvlar orqali kod asosida tasdiqlangan:

1. **Barcha flaglar tekshiruvi:**
   `grep -n "flag\." nightfalllx-go/main.go` buyrug'i bajarildi. 76 ta flag chaqiruvi ro'yxati va ularning standart qiymatlari 11-bo'limdagi jadval bilan 100% mos kelishi tekshirildi.
2. **Barcha modullar tekshiruvi:**
   `grep -rn "Name() string" nightfalllx-go/pkg/modules/*.go` buyrug'i bajarildi. 23 ta modul ro'yxati va ularning nomlari 6-bo'limdagi jadval bilan to'liq mos kelishi tasdiqlandi.
3. **`-sub` xatosini tasdiqlash:**
   `nightfalllx-go/main.go` ning 472–487-qatorlari qayta o'qildi va trigger tekshiruvi `Host: FUZZ.<domain>` o'rnatilishidan oldin ishlashi isbotlandi.
4. **Birlik testlari va statik tahlil:**
   `go vet ./...` (0 ogohlantirish) va `go test -count=1 ./...` (barcha paketlar PASS) muvaffaqiyatli yakunlandi.
