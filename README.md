# ssl.ee — SSL-sertifikaadi kontrollija

Tume ja modernne veebileht, kus saab ühe klikiga kontrollida domeeni
SSL/TLS-sertifikaadi kehtivust: kuni see kehtib, kes selle välja andis ja
milliseid aadresse see kaitseb.

## Failid

| Fail           | Otstarve                                       |
| -------------- | ---------------------------------------------- |
| `index.html`   | Lehe struktuur (eesti + inglise keeles)        |
| `styles.css`   | Tume visuaal (rohelsed/sinised aktsendid)     |
| `app.js`       | Kontrollimise loogika, i18n, ajalugu          |
| `api-docs.html`| API dokumentatsioon (ET/EN), link lehe päises  |
| `api/worker.js`| Eraldi Cloudflare Worker: PEM / täielik ahel   |
| `api/wrangler.toml` | Workeri juurutuskonfiguratsioon          |
| `favicon.svg`  | Lehe ikoon (rohkli lukk)                       |

## Kuidas töötab

Kõik päringud käivad **kasutaja brauseris** – serverit ega andmebaasi pole vaja.

1. **Cert Spotter** (primaarne) – Certificate Transparency logidest loetakse
   domeeni uusim sertifikaat: kehtivusajad, väljaandja, kaitstud domeenid (SAN),
   SHA-256 sõrmejälg ja tühistamise staatus. Vastab CORS-iga, API-võtit pole vaja.
2. **crt.sh** (varu) – kasutatakse, kui esimene allikas ei vasta.
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
- Keelevalik (ET/EN) jäetakse meelde `localStorage`-i, ajalugu samuti.
- Keeeltõlkeid saab täiendada `app.js` failis sõnastikes `I18N.et` / `I18N.en`.
- ICS-fail ja kõik uued kontrollid (CT/ahela võrdlus, CAA/DNSSEC) töötavad
  ainult brauseris – ükski domeen ega kalendriandmete sisu ei lähe ssl.ee serverisse.
