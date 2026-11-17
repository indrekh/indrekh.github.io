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
   see ahel just seda, mida server parasjagu teenindab. Rikke korral kuvatakse
   veateade, leht jääb kasutatavaks.

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

## Märkused

- CT logidest kuvatakse **uusim välja antud** sertifikaat; server teenindab
  mõnikord varasemat või muud – seepärast on lehel ka SSL Labsi süvalink.
- Keelevalik (ET/EN) jäetakse meelde `localStorage`-i, ajalugu samuti.
- Keeeltõlkeid saab täiendada `app.js` failis sõnastikes `I18N.et` / `I18N.en`.
