# ssl.ee — SSL-sertifikaadi kontrollija

Tume (või heledaks lülitatav) ja modernne veebileht, kus saab ühe klikiga kontrollida domeeni
SSL/TLS-sertifikaadi kehtivust: kuni see kehtib, kes selle välja andis ja
milliseid aadresse see kaitseb.

## Failid

| Fail           | Otstarve                                       |
| -------------- | ---------------------------------------------- |
| `index.html`   | Eestikeelne avaleht (`/`)                      |
| `en/index.html`| Ingliskeelne avaleht (`/en/`)                  |
| `styles.css`   | Tume/hele visuaal (rohelsed/sinised aktsendid)|
| `app.js`       | Kontrollimise loogika, i18n, ajalugu          |
| `api-docs.html`| API dokumentatsioon (ET)                       |
| `en/api-docs.html` | API dokumentatsioon (EN)                   |
| `pem.html`     | PEM-i dekodeerija (ET)                         |
| `en/pem.html`  | PEM-i dekodeerija (EN)                         |
| `artiklid/`    | Kolm eestikeelset juhendit: sertifikaadi uuendamine, PEM-fail, CAA ja DNSSEC |
| `en/artiklid/` | Kolm ingliskeelset juhendit (samad teemad, `hreflang` paaridena) |
| `sitemap.xml`  | Sitemap koos ET/EN `hreflang` alternatiividega |
| `api/worker.js`| Eraldi Cloudflare Worker: PEM / täielik ahel   |
| `api/wrangler.toml` | Workeri juurutuskonfiguratsioon          |
| `favicon.svg`  | Lehe ikoon (rohkli lukk)                       |

## Kuidas töötab

Kõik päringud käivad **kasutaja brauseris** – serverit ega andmebaasi pole vaja.

1. **Cert Spotter** (primaarne) – Certificate Transparency logidest loetakse
   domeeni uusim sertifikaat: kehtivusajad, väljaandja, kaitstud domeenid (SAN),
   SHA-256 sõrmejälg ja tühistamise staatus. Vastab CORS-iga, API-võtit pole vaja.
2. **crt.sh** (varu ja ajalugu) – kasutatakse, kui esimene allikas ei vasta.
   Väljaandmise ajalugu loetakse nüüd oma Cloudflare Workeri
   (`GET /api/history?d=domeen.ee`) kaudu, sest crt.sh-l endal puudub CORS ja
   otsepäring brauseris ebaõnnestub. Worker on varumeetodina alles ka otsepäring.
3. **MDN HTTP Observatory** (valikuline boonus) – HTTP turvapäiste skoor (A+…F).
   Keelamiseks muuda `app.js` failis `CONFIG.observatory` väärtuseks `false`.
4. **Täielik sertifikaadivaade** – Cert Spotteri PEM-andmetest loetakse otse
   brauseris (ASN.1 parser, ilma väliste teekideta) seerianumber, subjekt (DN),
   allkirja algoritm ja avaliku võtme tüüp/suurus; PEM-i saab kopeerida või
   ühe sertifikaadina `.pem`-failina alla laadida.
5. **Väljaandmise ajalugu** – crt.sh andmetest kuvatakse viimased 6 väljaannet
   ajateljel, 12 kuu statistika ja märkus mitme eri väljaandja kohta. Ajalugu
   laaditakse taustal ega blokeeri põhitulemust; rikke korral peidetakse.
6. **Täielik ahel** – „Kopeeri täielik ahel" ja „Laadi alla täielik ahel" küsivad
   Trustico SSL Toolsi API-st serveri reaalselt saadetud sertifikaadid
   (leht → vahepealsed → juur). Kopeerimine annab tervikliku PEM-i lõikelauale,
   allalaadimine loob ühe `.pem`-faili. API-võtit pole vaja, CORS on lubatud.
   Keelamiseks muuda `CONFIG.chain = false`. Erinevalt CT-logide vaatest näitab
   see ahel just seda, mida server parasjagu teenindab. PEM-i plokis kuvatakse
   ühe sertifikaadi PEM vasakul ja täielik ahel paremal (kitsas ekraanil
   virnastatakse). Ahel laaditakse taustal ja ühte domeeni laaditud ahelat
   kasutatakse uuesti nii kuvamisel, kopeerimisel kui allalaadimisel – seega
   tehakse võrgupäring ainult üks kord. Rikke korral kuvatakse veateade, leht
   jääb kasutatavaks.
7. **Jagatav kontrollilink ja tulemuse kopeerimine** – `ssl.ee/?d=domeen.ee`
   käivitab kontrolli automaatselt. Tulemuse all olevad nupud kopeerivad
   jagatava lingi (mobiilil kasutatakse vajadusel natiivset jagamist) või
   kogu tulemuse tekstina (staatus, väljaandja, kehtivus, SAN-id, sõrmejälg).
8. **Hariv lisasisu** – tulemuskardi väljadel on lühiselgitused ja lehe all
   on sõnastik väljade kohta ning samm-sammult juhend sertifikaadi uuendamiseks
   Let's Encrypti ja Certbotiga (sh automaatne uuendamine ja Cloudflare'i nipp).
9. **Eraldi curl-API** – `api/worker.js` on eraldi Cloudflare Worker, mis tagastab
   kas ühe sertifikaadi PEM-i või täieliku ahela. Põhileht jääb staatiliseks.
   Dokumentatsioon ja curl-näited asuvad lehel `api-docs.html` (link päises).

10. **ICS meeldetuletus** – nupp „Lisa meeldetuletus kalendrisse aegumise kohta" loob brauseris
    kalendrisündmuse 30 päeva enne sertifikaadi aegumist (`.ics`, koos
    `VALARM`-iga) ja laadib selle alla kui `domeen-ssl-reminder.ics`. Serverit
    ega e-posti aadressi ei vaja.
11. **CT logi vs serveri ahel** – võrdleme Cert Spotteri lehe SHA-256 sõrmejälge
    Trustico ahela lehega (`depth: 0`). Kui server teenindab teist sertifikaati,
    kuvatakse soovituslik hoiatus koos mõlema sõrmejäljega. Vastasel juhul
    kinnitame, et lehed ühtivad. Kui usaldusahelat ei saada, kuvatakse
    neutraalne teade, et võrdlus ei õnnestunud.
    Trustico tagastab sõrmejälje otse; varumeetodina arvutatakse see PEM-ist
    brauseri `crypto.subtle` abil. Ainult crt.sh varuallika kasutamisel (puudub
    sõrmejälg) märgime, et võrdlus pole võimalik.
12. **CAA ja DNSSEC** – Cloudflare DNS-over-HTTPS kaudu loetakse CAA-kirjed
    (lubatud sertifikaadiasutused, sh `issuewild`) ja DNSSEC-i autentimisolek
    (`AD` lipp). Andmed kuvatakse eraldi panelina; päringu ebaõnnestumisel
    plokk peidetakse. Keelamiseks muuda `CONFIG.dns = false`.
13. **Ahela visuaalne puu** – Trustico vastusest joonistatakse vertikaalne puu
    leht → vahepealsed CA-d → juur. Iga samm näitab subjekti, väljaandjat,
    kehtivuse lõppu ja lühikest SHA-256 sõrmejälge. Andmed laaditakse samast
    vahemällu salvestatud ahelapäringust, seega ei teki täiendavat võrguliiklust.
14. **curl / OpenSSL käsud** – PEM-i ploki nupud kopeerivad otse kasutatavad
    käsud: `curl` laeb sertifikaadi eraldi API-st (`/api/pem?d=...`) `.pem`-faili,
    OpenSSL-käsk suunab sama PEM-i toru kaudu `openssl x509` analüüsiks.
15. **Hele/tume teema** – päises olev nupp lülitab teemat nii kontrollijas kui
    ka API-dokumentatsioonis; valik salvestatakse `localStorage`'i
    (`ssl-ee-theme`) ja rakendatakse enne CSS-i laadimist, et vältida vilksatust.
    Vaikimisi on endiselt tume teema.
16. **Apex + www kõrvuti** – nupp „+ Võrdle apex ja www" kontrollib mõlemat
    hosti (`domeen.ee` ja `www.domeen.ee`) ühe klikiga ja näitab kahes veerus
    staatuse, allesjäänud päevad ja väljaandja. Iga veeru alt pääseb detailtulemusse.
    Kui sisestati `www.`-variant, võetakse aluseks apex-domeen.
17. **crt.sh ajaloo CORS-i parandus** – brauser küsib ajaloo läbi oma Workeri
    endpointi `/api/history`, mis tagastab normaliseeritud GT-logi kirjed
    (`not_before`, `not_after`, `name_value`, `issuer_name`). Kui API pole
    juurutatud, proovitakse varumeetodina otse crt.sh-i; ajalugu peidetakse
    endiselt vaikselt, kui mõlemad allikad ebaõnnestuvad.
18. **Kontrolli leiud** – tulemuse ülaossa koonduvad automaatsed järeldused
    olemasolevatest andmetest: hosti katvus, aegumine, kehtivusaja pikkus
    (CA/B Forum 398 päeva), avaliku võtme tugevus, allkirja algoritm,
    tühistamine, metamärk, CT-logimine, ahela terviklikkus, CAA, DNSSEC ja
    HTTP turvapäiste hinne. Probleemid ja hoiatused kuvatakse kohe, ülejäänud
    kontrollid on kokkuvolditud nimekirjas. Leiud arvutatakse brauseris ja
    uuendatakse, kui ahela, DNS-i või Observatory andmed hiljem saabuvad.
19. **PEM-i dekodeerija** – eraldi alamlehel [`pem.html`](pem.html) saab
    ühe või mitme sertifikaadi PEM-id (või tühjade ridadega eraldatud paljad
    base64-plokid) kleepida ja kohapeal lahti lugeda: subjekt, väljaandja,
    seerianumber, kehtivus, avalik võti, allkirja algoritm, SHA-256 sõrmejälg ja
    SAN-nimed. Iga sertifikaat saab oma kaardi ja kehtivusmärgi; vigaste
    plokkide kohta kuvatakse märkus. Oma ASN.1 parser loeb ka
    `UTCTime`/`GeneralizedTime` kuupäevad ja `subjectAltName` laienduse.
    Dekodeerimine ei tee ühtegi võrgupäringut. Lehele pääseb avalehe päises
    oleva **PEM**-lingi kaudu (API kõrval) ning API-docside päisest.

Täpseks kättesaamise analüüsiks (protokollid, šifrid, usaldusahel) suunab leht
kasutaja SSL Labsi raportile.

## Kohalik eelvaade

Topeltklõpsa `index.html`-il või serveeri kausta:

```bash
python -m http.server 8080
# või
npx serve .
```

## Avaldamine aadressile ssl.ee

Leht on puhas staatiline – sobib igale majutajale:

1. **Zone.ee / Elkdata / Veebimajutus** – laadi failid üles veebijuurkausta
   (`public_html` vms). Domeen ssl.ee peab juba suunatud olema majutusele.
2. **Cloudflare Pages / Netlify / GitHub Pages** – loo projekt, lohista kaust,
   seosta kohandatud domeen `ssl.ee` (DNS: CNAME).
3. Lülita majutuse juures HTTPS sisse – SSL-kontrollijal peab ise `https://ssl.ee`
   ilus roheline lukk olema. (Cloudflare/Netlify annavad sertifikaadi tasuta.)

### curl-API juurutamine (valikuline)

```bash
cd api
# 1. api/wrangler.toml sisaldab juba route = { pattern = "ssl.ee/api/*", zone_name = "ssl.ee" }
#    (oma tsoon tuleb vajadusel asendada)
wrangler deploy
curl https://ssl.ee/api/health
```

Endpointid:

```bash
curl "https://ssl.ee/api/pem?d=wikipedia.org"    # ainult PEM
curl "https://ssl.ee/api/chain?d=wikipedia.org"  # ainult täielik ahel
curl "https://ssl.ee/api/?d=wikipedia.org"       # mõlemad JSON-ina
```

Täpsemad näited, parameetrid ja veakoodid: `api-docs.html`.

## Märkused

- CT logidest kuvatakse **uusim välja antud** sertifikaat; server teenindab
  mõnikord varasemat või muud – seepärast on lehel ka SSL Labsi süvalink.
- Keel tuleb URL-ilt: eestikeelne leht on `/`, ingliskeelne `/en/`. Päises olev
  ET/EN valik on tavaline link keeleversioonide vahel; `hreflang`-viited ja
  `sitemap.xml` alt-lingid on mõlemas suunas. Ajalugu salvestatakse endiselt
  `localStorage`-i.
- Keeletõlkeid saab täiendada `app.js` failis sõnastikes `I18N.et` / `I18N.en`
  ning `api-docs.html` ja `pem.html` inline-sõnastikes.
- ICS-fail ja kõik uued kontrollid (CT/ahela võrdlus, CAA/DNSSEC) töötavad
  ainult brauseris – ükski domeen ega kalendriandmete sisu ei lähe ssl.ee serverisse.
