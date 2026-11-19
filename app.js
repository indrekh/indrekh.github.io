/* ssl.ee — SSL-sertifikaadi kontrollija
 * Staatiline leht: kõik päringud käivad kasutaja brauseris.
 * Andmeallikad: Cert Spotter (CT logid, primaarne), crt.sh (varu),
 * MDN HTTP Observatory (HTTP turvapäiste skoor, boonus),
 * Trustico SSL Tools (täielik ahel + CT/ahela võrdlus),
 * Cloudflare DNS-over-HTTPS (CAA ja DNSSEC).
 */
(() => {
  'use strict';

  /* ---------- Config ---------- */
  const CONFIG = {
    warnDays: 30,        // alla selle jäänud päevade arv = hoiatus
    sanPreview: 8,       // mitu domeeni enne "näita kõiki"
    historyMax: 8,
    timeouts: { certspotter: 15000, crtsh: 30000, observatory: 20000, chain: 25000, dns: 10000 },
    observatory: true,   // HTTP turvapäiste skoor (MDN HTTP Observatory)
    chain: true,         // täieliku sertifikaadiahela allalaadimine (Trustico SSL Tools)
    dns: true,           // CAA ja DNSSEC (Cloudflare DNS-over-HTTPS)
    reminderDays: 30,    // meeldetuletus enne sertifikaadi aegumist
  };

  const CS_API = 'https://api.certspotter.com/v1/issuances';
  const CRTSH_API = 'https://crt.sh/';
  const OBS_API = 'https://observatory-api.mdn.mozilla.net/api/v2/scan';
  const CHAIN_API = 'https://tools.trustico.com/api/chain/analyze-url';
  const DNS_API = 'https://cloudflare-dns.com/dns-query';
  const API_BASE = 'https://ssl.ee/api';
  const SSLLABS_URL = 'https://www.ssllabs.com/ssltest/analyze.html?d=';

  /* ---------- i18n ---------- */
  const I18N = {
    et: {
      'meta.title': 'ssl.ee — SSL-sertifikaadi kontrollija',
      'nav.api': 'API',
      'nav.apiAria': 'API dokumentatsioon',
      'nav.pem': 'PEM',
      'nav.pemAria': 'PEM-i dekodeerija',
      'nav.theme': 'Vaheta heledat ja tumedat teemat',
      'hero.badge': 'Tasuta tööriist · andmed Certificate Transparency logidest',
      'hero.title': 'Kas sinu domeeni <span class="grad">SSL-sertifikaat</span> on veel kehtiv?',
      'hero.subtitle': 'Sisesta domeeninimi ja vaata ühe klikiga, kuni sertifikaat kehtib, kes selle välja andis ja milliseid aadresse see kaitseb.',
      'form.placeholder': 'sinudomeen.ee',
      'form.ariaLabel': 'Kontrollitav domeen',
      'form.button': 'Kontrolli',
      'form.compare': '+ Võrdle apex ja www',
      'hero.try': 'Proovi:',
      'hero.privacy': 'Kõik päringud käivad otse sinu brauseris – ssl.ee ei salvesta kontrollitavaid domeene.',
      'scan.ct': 'Küsin sertifikaadi andmeid (Cert Spotter, CT logid)…',
      'scan.fallback': 'Esimene allikas ei vastanud, proovin varuallikat crt.sh…',
      'error.title': 'Kontroll ebaõnnestus',
      'error.invalidDomain': 'See ei tundu korrektne domeeninimi. Sisesta näiteks näidis.ee',
      'error.notFound': 'Domeenile {host} ei leitud Certificate Transparency logidest ühtegi sertifikaati. Kontrolli õigekirja.',
      'error.failed': 'Andmeallikad ei vastanud praegu (võrguviga või liiga sage pärimine). Palun proovi mõne hetke pärast uuesti.',
      'error.links': 'Vahepeal saad domeeni kontrollida ka käsitsi:',
      'status.valid': 'Sertifikaat on kehtiv',
      'status.expiring': 'Aegub varsti',
      'status.expired': 'Sertifikaat on aegunud',
      'chip.expiredAgo': 'aegus {n} päeva tagasi',
      'chip.expiredToday': 'aegus täna',
      'gauge.label': 'päeva',
      'gauge.caption.valid': 'kehtivust veel alles',
      'gauge.caption.expired': 'sertifikaat ei ole enam kehtiv',
      'detail.issuer': 'Väljaandja',
      'detail.validFrom': 'Kehtiv alates',
      'detail.validUntil': 'Kehtib kuni',
      'detail.fingerprint': 'Sõrmejälg (SHA-256)',
      'hint.issuer': 'Asutus, mis sertifikaadi välja andis ja allkirjastas.',
      'hint.validFrom': 'Sellest kuupäevast on sertifikaat kehtiv.',
      'hint.validUntil': 'Pärast seda näitab brauser hoiatuslehte.',
      'hint.fingerprint': 'Unikaalne identifikaator sertifikaadi tuvastamiseks.',
      'share.copyLink': 'Kopeeri jagatav link',
      'share.copyResult': 'Kopeeri tulemus',
      'share.linkCopied': 'Jagatav link kopeeritud!',
      'share.resultCopied': 'Tulemus kopeeritud!',
      'share.title': 'SSL-sertifikaadi kontroll',
      'share.sans': 'Kaitstud domeenid',
      'share.source': 'Andmed',
      'learn.title': 'Sertifikaadi uuendamine ja tulemuse mõistmine',
      'learn.fieldsTitle': 'Mida tulemus tähendab?',
      'learn.glossIssuer': 'Väljaandja',
      'learn.glossIssuerText': 'Asutus (CA), mis sertifikaadi välja andis ja digitaalselt allkirjastas – näiteks Let\'s Encrypt või Google Trust Services.',
      'learn.glossValid': 'Kehtivusaeg',
      'learn.glossValidText': 'Sertifikaat kehtib ainult märgitud ajavahemikul. Pärast lõppkuupäeva kuvab brauser hoiatuslehe.',
      'learn.glossFp': 'Sõrmejälg',
      'learn.glossFpText': 'Sertifikaadi unikaalne SHA-256 identifikaator, mille järgi saab kindlaks teha, kas server teenindab just seda sertifikaati.',
      'learn.glossSan': 'Kaitstud domeenid',
      'learn.glossSanText': 'Kõik aadressid, mille jaoks sertifikaat kehtib (SAN). Kui sinu aadressi seal pole, ilmub brauseris hoiatus.',
      'learn.renewTitle': 'Kuidas sertifikaati uuendada?',
      'learn.renewIntro': 'Enamikul juhtudel piisab Let\'s Encrypti tasuta sertifikaadist ja Certbotist. Uuenda sertifikaat vähemalt 30 päeva enne aegumist.',
      'learn.step1': 'Paigalda Certbot: <code>sudo apt install certbot python3-certbot-nginx</code> (Nginx) või <code>python3-certbot-apache</code> (Apache).',
      'learn.step2': 'Hangi ja paigalda sertifikaat: <code>sudo certbot --nginx -d sinudomeen.ee</code> (või <code>--apache</code>).',
      'learn.step3': 'Kontrolli automaatset uuendamist: <code>sudo certbot renew --dry-run</code>. Certbot lisab ise ajastatud ülesande.',
      'learn.tip': 'Nipp: kui kasutad Cloudflare\'i, saab SSL-i hallata ka selle juhtpaneelilt – siis ei pea Certboti serveris käitama.',
      'certdetails.title': 'Sertifikaadi tehnilised andmed',
      'certdetails.serial': 'Seerianumber',
      'certdetails.subject': 'Subjekt (DN)',
      'certdetails.algorithm': 'Allkirja algoritm',
      'certdetails.key': 'Avalik võti',
      'certdetails.pemToggle': 'Näita(laadi alla) sertifikaadi PEM-i ja sertifikaadi ahelat',
      'certdetails.copy': 'Kopeeri PEM',
      'certdetails.copied': 'Kopeeritud!',
      'certdetails.copyFail': 'Kopeerimine ei õnnestunud.',
      'certdetails.copyChain': 'Kopeeri täielik ahel',
      'certdetails.copyingChain': 'Kopeerin ahelat…',
      'certdetails.chainCopied': 'Täielik ahel kopeeritud ({n} sertifikaati).',
      'certdetails.downloadPem': 'Laadi alla PEM',
      'certdetails.pemOk': 'Sertifikaadi PEM alla laaditud.',
      'certdetails.precert': 'eel-sertifikaat (precert)',
      'certdetails.downloadChain': 'Laadi alla täielik ahel',
      'certdetails.downloading': 'Laadin ahelat…',
      'certdetails.chainOk': 'Täielik ahel alla laaditud ({n} sertifikaati).',
      'certdetails.chainFail': 'Ahela laadimine ei õnnestunud. Proovi hiljem uuesti.',
      'certdetails.chainNote': 'Ahel pärineb serveri reaalselt saadetud sertifikaatidest (Trustico SSL Tools).',
      'certdetails.pemColumn': 'Sertifikaadi PEM',
      'certdetails.chainColumn': 'Täielik ahel (PEM)',
      'certdetails.chainLoading': 'Laadin ahelat…',
      'certdetails.chainLoadFail': 'Ahela sisu ei õnnestunud laadida. Proovi hiljem uuesti.',
      'cmd.curl': 'Kopeeri curl-käsk',
      'cmd.openssl': 'Kopeeri openssl-käsk',
      'cmd.curlCopied': 'curl-käsk kopeeritud!',
      'cmd.opensslCopied': 'openssl-käsk kopeeritud!',
      'reminder.button': 'Lisa meeldetuletus kalendrisse aegumise kohta',
      'reminder.ok': 'Kalendrisündmus alla laaditud (.ics).',
      'reminder.title': 'Uuenda SSL-sertifikaat: {host}',
      'reminder.desc': 'Sertifikaadi {host} kehtivus lõppeb {date}. Uuenda vähemalt 30 päeva enne aegumist.',
      'reminder.alarm': 'Uuenda SSL-sertifikaat: {host}',
      'chaincheck.title': 'CT logi ja serveri ahel',
      'chaincheck.ok': 'CT logi leht ühtib serveri saadetud lehega.',
      'chaincheck.mismatch': 'Tähelepanu: server teenindab teist lehesertifikaati kui CT logi.',
      'chaincheck.noFp': 'Võrdlus ei ole võimalik – CT logi sõrmejälg puudub.',
      'chaincheck.unknown': 'Võrdlus ei õnnestunud – serveri ahelat või sõrmejälge ei saadud kätte.',
      'chaincheck.ctFp': 'CT logi: {fp}',
      'chaincheck.chainFp': 'Serveri ahel: {fp}',
      'chaincheck.note': 'Soovitus: kui server teenindab teist sertifikaati, kontrolli serveri või CDN-i konfiguratsiooni.',
      'chainTree.title': 'Sertifikaadiahela puu',
      'chainTree.leaf': 'Leht',
      'chainTree.intermediate': 'Vahepealne CA',
      'chainTree.root': 'Juursertifikaat',
      'chainTree.issuedBy': 'Väljaandja: {name}',
      'chainTree.validUntil': 'Kehtib kuni {date}',
      'chainTree.expiring': 'Aegub {n} päeva pärast',
      'chainTree.expired': 'Aegunud',
      'chainTree.count': '{n} sertifikaati',
      'chainTree.depth': 'sügavus {n}',
      'chainTree.loading': 'Laadin sertifikaadiahelat…',
      'chainTree.fail': 'Ahela andmeid ei õnnestunud laadida.',
      'chainTree.note': 'Puu näitab serveri saadetud sertifikaate (Trustico SSL Tools). Leht on sinu domeeni sertifikaat, juur on usaldusankur.',
      'dns.title': 'CAA ja DNSSEC',
      'dns.provider': 'Cloudflare DNS-over-HTTPS',
      'dns.caa': 'Lubatud sertifikaadiasutused (CAA)',
      'dns.dnssec': 'DNSSEC',
      'dns.caaNone': 'CAA-kirjet pole – väljaandmise piiranguid pole avaldatud.',
      'dns.caaRecord': '{n} kirje',
      'dns.caaRecords': '{n} kirjet',
      'dns.caaWild': 'aldomeenid',
      'dns.dnssecOn': 'Kasutusel · AD = true',
      'dns.dnssecOff': 'Ei ole tuvastatud · AD = false',
      'dns.note': 'CAA määrab, milline asutus tohib sellele domeenile sertifikaadi välja anda. DNSSEC kaitseb DNS-vastuseid võltsimise eest.',
      'dns.fail': 'DNS-i andmed pole praegu saadaval. Proovi hiljem uuesti.',
      'timeline.title': 'Väljaandmise ajalugu',
      'timeline.summary': 'Viimase 12 kuu jooksul {n} väljaannet',
      'timeline.summaryOne': 'Viimase 12 kuu jooksul 1 väljaanne',
      'timeline.issuers': '{n} väljaandjat',
      'timeline.issuersOne': '1 väljaandja',
      'timeline.note': 'Domeenile on viimase aasta jooksul sertifikaate välja antud mitmelt väljaandjalt:',
      'compare.title': 'Apex ja www kõrvuti',
      'compare.subtitle': '{apex} ja www.{apex}',
      'compare.scan': 'Kontrollin mõlemat domeeni…',
      'compare.valid': 'Kehtiv',
      'compare.expiring': 'Aegub varsti',
      'compare.expired': 'Aegunud',
      'compare.days': '{n} päeva alles',
      'compare.issuer': 'Väljaandja: {name}',
      'compare.notFound': 'CT logist ei leitud sertifikaati',
      'compare.failed': 'Kontroll ebaõnnestus',
      'compare.open': 'Vaata detailtulemust',
      'compare.bothOk': 'Mõlemal domeenil on kehtiv sertifikaat.',
      'compare.partial': 'Vähemalt ühe domeeni sertifikaat puudub või on aegunud.',
      'compare.note': 'Apex ja www on eraldi hostid – ühe domeeni sertifikaat ei pruugi kaitsta teist. Kontrolli mõlemat.',
      'f.title': 'Kontrolli leiud',
      'f.summaryFail': '{n} probleemi',
      'f.summaryFailOne': '1 probleem',
      'f.summaryWarn': '{n} hoiatust',
      'f.summaryWarnOne': '1 hoiatus',
      'f.summaryOk': 'Kõik kontrollid on korras',
      'f.allChecks': 'Kõik kontrollid ({n})',
      'f.hostOk': 'Sertifikaat katab domeeni {host}',
      'f.hostOkD': 'Sertifikaadi nimede hulgas on {host}, seega brauser aktsepteerib selle domeeni.',
      'f.hostFail': 'Sertifikaat ei kata domeeni {host}',
      'f.hostFailD': 'Sertifikaadi nimede hulgas ei ole {host}. Brauser näitaks selle domeeni jaoks turvahoiatust.',
      'f.expiryOk': 'Sertifikaat kehtib veel {n} päeva',
      'f.expiryOkD': 'Uuenda sertifikaat enne {date}, et vältida veebilehe katkestust.',
      'f.expiryWarn': 'Sertifikaat aegub {n} päeva pärast',
      'f.expiryWarnD': 'Uuenda sertifikaat kohe – pärast {date} näitab brauser külastajatele hoiatust.',
      'f.expiryFail': 'Sertifikaat on aegunud',
      'f.expiryFailD': 'Sertifikaat aegus {date}. Kuni uuendamiseni näitab brauser külastajatele turvahoiatust.',
      'f.validityOk': 'Kehtivusaeg {n} päeva jääb lubatud piiresse',
      'f.validityOkD': 'CA/B Forum piirang: avalikult usaldatud sertifikaat ei tohi kehtida üle 398 päeva.',
      'f.validityWarn': 'Kehtivusaeg {n} päeva ületab 398 päeva piiri',
      'f.validityWarnD': 'Chrome ja Safari ei pruugi nii pika kehtivusajaga sertifikaati usaldada. Väljasta lühema kehtivusajaga sertifikaat.',
      'f.keyOk': 'Avalik võti: {key}',
      'f.keyOkD': 'Võtme tugevus vastab tänastele nõuetele (vähemalt RSA 2048 või EC P-256).',
      'f.keyFail': 'Nõrk avalik võti: {key}',
      'f.keyFailD': 'Vähem kui 2048-bitist RSA võtit peetakse ebaturvaliseks. Väljasta uus sertifikaat RSA 2048+ või EC P-256 võtmega.',
      'f.keyInfo': 'Avalik võti: {key}',
      'f.keyInfoD': 'Võtme tüüpi ei õnnestunud täpselt tuvastada. Kontrolli seda OpenSSL-iga.',
      'f.sigOk': 'Allkirja algoritm: {alg}',
      'f.sigOkD': 'Kasutusel on turvaline räsi (SHA-256 või tugevam).',
      'f.sigFail': 'Nõrk allkirja algoritm: {alg}',
      'f.sigFailD': 'SHA-1 või MD5 allkirja peavad brauserid ebaturvaliseks. Väljasta sertifikaat uuesti SHA-256-ga.',
      'f.sigInfo': 'Allkirja algoritm: {alg}',
      'f.sigInfoD': 'Tundmatu algoritm. Kontrolli sertifikaati OpenSSL-iga.',
      'f.revokedFail': 'Sertifikaat on tühistatud',
      'f.revokedFailD': 'Väljaandja on sertifikaadi tühistanud. Väljasta uus sertifikaat kohe.',
      'f.wildcardInfo': 'Sertifikaat kasutab metamärki ({pattern})',
      'f.wildcardInfoD': 'Metamärk katab kõik sama taseme alamdomeenid. Veendu, et see on soovitud ulatus.',
      'f.ctOk': 'Sertifikaat on CT-logides',
      'f.ctOkD': 'Sertifikaat on Certificate Transparency logides (allikas: {source}) – Chrome ja Safari nõuavad seda.',
      'f.chainOk': 'Ahelas on {n} sertifikaati',
      'f.chainOkD': 'Server saadab lehe ja vähemalt ühe vahepealse sertifikaadi, seega kliendid saavad ahela ise lõpetada.',
      'f.chainMissingWarn': 'Ahelas on ainult lehtsertifikaat',
      'f.chainMissingWarnD': 'Server ei saada vahepealset sertifikaati. Osa kliente ei suuda ahelat ise täiendada. Lisa vahepealne sertifikaat serveri seadistusse.',
      'f.chainRootInfo': 'Server saadab ka juursertifikaadi',
      'f.chainRootInfoD': 'Juur pole vajalik ja suurendab iga ühenduse mahtu. Eemalda see serveri ahelast.',
      'f.chainExpiryWarn': 'Ahela sertifikaat aegub varsti: {name}',
      'f.chainExpiryWarnD': 'Vahepealne sertifikaat aegub {date}. Võta ühendust oma CA-ga ja uuenda ahel.',
      'f.chainCheckInfo': 'CT-logi ja serveri leht erinevad',
      'f.chainCheckInfoD': 'See võib olla normaalne, kui domeenil on mitu kehtivat sertifikaati (nt CDN-i puhul). Kontrolli serveri seadistust, kui see pole ootuspärane.',
      'f.caaOk': 'CAA-kirjed on olemas ({n})',
      'f.caaOkD': 'CAA-kirjed piiravad, millised CA-d tohivad domeenile sertifikaate väljastada.',
      'f.caaInfo': 'CAA-kirjeid ei ole',
      'f.caaInfoD': 'CAA kirjed takistavad volitamata CA-del sertifikaate väljastada. Näide: issue "letsencrypt.org"',
      'f.dnssecOk': 'DNSSEC on aktiivne',
      'f.dnssecOkD': 'DNS-vastused on krüptograafiliselt allkirjastatud.',
      'f.dnssecInfo': 'DNSSEC ei ole aktiivne',
      'f.dnssecInfoD': 'DNSSEC kaitseb DNS-vastuseid võltsimise eest. Küsi DNSSEC-tuge oma DNS-teenusepakkujalt.',
      'f.headersOk': 'HTTP turvapäiste hinne: {grade}',
      'f.headersOkD': 'Turvapäised (HSTS, CSP jt) on hästi seadistatud.',
      'f.headersInfo': 'HTTP turvapäiste hinne: {grade}',
      'f.headersInfoD': 'Päised on osaliselt seadistatud. Vaata üksikasju MDN HTTP Observatoryst.',
      'f.headersWarn': 'HTTP turvapäiste hinne: {grade}',
      'f.headersWarnD': 'Mitmed turvapäised on puudulikud. Vaata soovitusi MDN HTTP Observatoryst.',
      'f.headersFail': 'HTTP turvapäiste hinne: {grade}',
      'f.headersFailD': 'Turvapäised on puudulikud või ohtlikult seadistatud. Paranda HSTS, CSP ja X-Content-Type-Options.',
      'sans.title': 'Kaitstud domeenid ({n})',
      'sans.more': 'Näita kõiki ({n})',
      'sans.less': 'Näita vähem',
      'badge.revoked': 'Tühistatud',
      'badge.revokedFull': 'Sertifikaat on väljaandja poolt tühistatud (revoked)',
      'advice.valid': 'Kõik on korras – järgmise uuendamiseni pole vaja midagi ette võtta.',
      'advice.expiring': 'Uuenda sertifikaat varakult, et vältida teenuse katkemist.',
      'advice.expired': 'Uuenda sertifikaat viivitamatult – muidu brauserid ei pruugi saiti enam avada.',
      'source.note': 'Andmed: Certificate Transparency logid ({source}) · kuvatud on uusim väljaanne',
      'obs.title': 'HTTP turvapäiste skoor',
      'obs.score': 'skoor {score}/100',
      'obs.link': 'Vaata täisraportit',
      'links.ssllabs': 'Süvaanalüüs: SSL Labs',
      'links.crtsh': 'Sertifikaadi ajalugu: crt.sh',
      'history.title': 'Hiljutised kontrollid',
      'history.clear': 'Tühjenda',
      'features.title': 'Miks sertifikaati regulaarselt kontrollida?',
      'feat1.title': 'Külastajate usaldus',
      'feat1.text': 'Aegunud sertifikaadiga saidi avamisel näitab brauser hoiatust ja külastaja lahkub kohe – koos temaga kaob ka usaldus.',
      'feat2.title': 'Otsingumootorid',
      'feat2.text': 'HTTPS on Google\'i järjestamise tegur. Vigase sertifikaadiga sait langeb otsingutulemustes oluliselt tagasi või kaob neist hoopis.',
      'feat3.title': 'Krüptitud liiklus',
      'feat3.text': 'SSL/TLS krüptib külastaja ja serveri vahelise ühenduse. Aegunud sertifikaat jätab andmed kuulatavaks ja muudetavaks.',
      'faq.title': 'Korduma kippuvad küsimused',
      'faq1.q': 'Mida see leht teeb?',
      'faq1.a': 'ssl.ee kontrollib domeeni SSL/TLS-sertifikaadi kehtivust: kuni see kehtib, kes selle välja andis ja milliseid aadresse see kaitseb. Piisab domeeninimest – vastus on olemas mõne sekundiga.',
      'faq2.q': 'Kust andmed tulevad?',
      'faq2.a': 'Sertifikaadi andmed loetakse Certificate Transparency logidest teenuse Cert Spotter kaudu (varuallikaks crt.sh), HTTP turvapäiste skoor tuleb MDN HTTP Observatoryst, täielik sertifikaadiahel ja CT/ahela võrdlus Trustico SSL Toolsi kaudu ning CAA ja DNSSEC Cloudflare DNS-over-HTTPS-i kaudu. Kõik päringud käivad otse sinu brauseris.',
      'faq3.q': 'Miks kuvatud info võib tegelikust erineda?',
      'faq3.a': 'CT logidest kuvatakse uusim välja antud sertifikaat. Server või CDN teenindab mõnikord varasemat või muud sertifikaati – täielikuks analüüsiks (sh protokollid ja šifrid) kasuta allpool olevat SSL Labsi linki.',
      'faq4.q': 'Mis tähendab „aegub varsti“?',
      'faq4.a': 'Sertifikaadile on jäänud alla 30 päeva. Soovitame uuendada kohe – nii ei satu leht uuenduse ununemise tõttu kättesaamatuks.',
      'faq5.q': 'Kas kasutamine on tasuta?',
      'faq5.a': 'Jah. ssl.ee on tasuta, ei nõua registreerimist ega kogu isikuandmeid. Küll võivad kehtida andmeallikate endi päringupiirangud.',
      'footer.tagline': 'Privaatsust austav SSL-sertifikaadi kontrollija – kõik päringud käivad sinu brauseris.',
      'footer.sources': 'Andmeallikad: Cert Spotter · crt.sh · MDN HTTP Observatory · Trustico · Cloudflare DNS',
      'footer.navCheck': 'Kontrolli sertifikaati',
      'footer.navLearn': 'Sertifikaadi uuendamine',
      'footer.navFaq': 'Korduma kippuvad küsimused',
      'footer.navApi': 'API dokumentatsioon',
    },
    en: {
      'meta.title': 'ssl.ee — SSL certificate checker',
      'nav.api': 'API',
      'nav.apiAria': 'API documentation',
      'nav.pem': 'PEM',
      'nav.pemAria': 'PEM decoder',
      'nav.theme': 'Switch between light and dark theme',
      'hero.badge': 'Free tool · data from Certificate Transparency logs',
      'hero.title': 'Is your domain\'s <span class="grad">SSL certificate</span> still valid?',
      'hero.subtitle': 'Enter a domain name and instantly see how long the certificate is valid, who issued it, and which hostnames it protects.',
      'form.placeholder': 'yourdomain.com',
      'form.ariaLabel': 'Domain to check',
      'form.button': 'Check',
      'form.compare': '+ Compare apex and www',
      'hero.try': 'Try:',
      'hero.privacy': 'All queries run directly in your browser – ssl.ee never stores the domains you check.',
      'scan.ct': 'Fetching certificate data (Cert Spotter, CT logs)…',
      'scan.fallback': 'Primary source unavailable, trying crt.sh backup…',
      'error.title': 'Check failed',
      'error.invalidDomain': 'That doesn\'t look like a valid domain name. Try e.g. example.com',
      'error.notFound': 'No certificates found for {host} in the Certificate Transparency logs. Check the spelling.',
      'error.failed': 'Data sources are unavailable right now (network issue or rate limiting). Please try again in a moment.',
      'error.links': 'In the meantime you can also check the domain manually:',
      'status.valid': 'Certificate is valid',
      'status.expiring': 'Expiring soon',
      'status.expired': 'Certificate has expired',
      'chip.expiredAgo': 'expired {n} days ago',
      'chip.expiredToday': 'expired today',
      'gauge.label': 'days',
      'gauge.caption.valid': 'of validity left',
      'gauge.caption.expired': 'certificate is no longer valid',
      'detail.issuer': 'Issuer',
      'detail.validFrom': 'Valid from',
      'detail.validUntil': 'Valid until',
      'detail.fingerprint': 'Fingerprint (SHA-256)',
      'hint.issuer': 'The authority (CA) that issued and signed the certificate.',
      'hint.validFrom': 'The certificate is valid from this date onward.',
      'hint.validUntil': 'After this date the browser shows a warning.',
      'hint.fingerprint': 'Unique identifier used to identify this exact certificate.',
      'share.copyLink': 'Copy share link',
      'share.copyResult': 'Copy result',
      'share.linkCopied': 'Share link copied!',
      'share.resultCopied': 'Result copied!',
      'share.title': 'SSL certificate check',
      'share.sans': 'Covered hostnames',
      'share.source': 'Data',
      'learn.title': 'Renewing a certificate and understanding the result',
      'learn.fieldsTitle': 'What the result means',
      'learn.glossIssuer': 'Issuer',
      'learn.glossIssuerText': 'The certificate authority (CA) that issued and digitally signed the certificate – for example Let\'s Encrypt or Google Trust Services.',
      'learn.glossValid': 'Validity',
      'learn.glossValidText': 'A certificate is valid only during the stated period. After the end date the browser displays a warning page.',
      'learn.glossFp': 'Fingerprint',
      'learn.glossFpText': 'A unique SHA-256 identifier that lets you verify the server is serving exactly this certificate.',
      'learn.glossSan': 'Covered hostnames',
      'learn.glossSanText': 'All addresses the certificate covers (SAN). If your address is not listed, the browser will show a warning.',
      'learn.renewTitle': 'How to renew a certificate',
      'learn.renewIntro': 'In most cases a free Let\'s Encrypt certificate and Certbot are enough. Renew at least 30 days before expiry.',
      'learn.step1': 'Install Certbot: <code>sudo apt install certbot python3-certbot-nginx</code> (Nginx) or <code>python3-certbot-apache</code> (Apache).',
      'learn.step2': 'Obtain and install the certificate: <code>sudo certbot --nginx -d example.com</code> (or <code>--apache</code>).',
      'learn.step3': 'Test automatic renewal: <code>sudo certbot renew --dry-run</code>. Certbot sets up the scheduled task for you.',
      'learn.tip': 'Tip: if you use Cloudflare, you can manage SSL from its dashboard instead – no Certbot needed on the server.',
      'certdetails.title': 'Certificate technical details',
      'certdetails.serial': 'Serial number',
      'certdetails.subject': 'Subject (DN)',
      'certdetails.algorithm': 'Signature algorithm',
      'certdetails.key': 'Public key',
      'certdetails.pemToggle': 'Show certificate PEM and certificate chain',
      'certdetails.copy': 'Copy PEM',
      'certdetails.copied': 'Copied!',
      'certdetails.copyFail': 'Could not copy.',
      'certdetails.copyChain': 'Copy full chain',
      'certdetails.copyingChain': 'Copying chain…',
      'certdetails.chainCopied': 'Full chain copied ({n} certificates).',
      'certdetails.downloadPem': 'Download PEM',
      'certdetails.pemOk': 'Certificate PEM downloaded.',
      'certdetails.precert': 'precertificate (precert)',
      'certdetails.downloadChain': 'Download full chain',
      'certdetails.downloading': 'Downloading chain…',
      'certdetails.chainOk': 'Full chain downloaded ({n} certificates).',
      'certdetails.chainFail': 'Could not load the chain. Please try again later.',
      'certdetails.chainNote': 'The chain comes from the certificates actually served by the server (Trustico SSL Tools).',
      'certdetails.pemColumn': 'Certificate PEM',
      'certdetails.chainColumn': 'Full chain (PEM)',
      'certdetails.chainLoading': 'Loading chain…',
      'certdetails.chainLoadFail': 'Could not load the chain content. Please try again later.',
      'cmd.curl': 'Copy curl command',
      'cmd.openssl': 'Copy OpenSSL command',
      'cmd.curlCopied': 'curl command copied!',
      'cmd.opensslCopied': 'OpenSSL command copied!',
      'reminder.button': 'Add reminder',
      'reminder.ok': 'Calendar event downloaded (.ics).',
      'reminder.title': 'Renew SSL certificate: {host}',
      'reminder.desc': 'The certificate for {host} expires on {date}. Renew at least 30 days before expiry.',
      'reminder.alarm': 'Renew SSL certificate: {host}',
      'chaincheck.title': 'CT log vs served chain',
      'chaincheck.ok': 'The CT-log leaf matches the leaf served by the server.',
      'chaincheck.mismatch': 'Advisory: the server serves a different leaf certificate than the CT log.',
      'chaincheck.noFp': 'Comparison is not possible – no CT-log fingerprint available.',
      'chaincheck.unknown': 'Comparison failed – the served chain or its fingerprint was unavailable.',
      'chaincheck.ctFp': 'CT log: {fp}',
      'chaincheck.chainFp': 'Served chain: {fp}',
      'chaincheck.note': 'If the server serves a different certificate, check the server or CDN configuration.',
      'chainTree.title': 'Certificate chain tree',
      'chainTree.leaf': 'Leaf',
      'chainTree.intermediate': 'Intermediate CA',
      'chainTree.root': 'Root certificate',
      'chainTree.issuedBy': 'Issued by: {name}',
      'chainTree.validUntil': 'Valid until {date}',
      'chainTree.expiring': 'Expires in {n} days',
      'chainTree.expired': 'Expired',
      'chainTree.count': '{n} certificates',
      'chainTree.depth': 'depth {n}',
      'chainTree.loading': 'Loading certificate chain…',
      'chainTree.fail': 'Could not load the chain data.',
      'chainTree.note': 'The tree shows the certificates served by the server (Trustico SSL Tools). The leaf is your domain\'s certificate; the root is the trust anchor.',
      'dns.title': 'CAA and DNSSEC',
      'dns.provider': 'Cloudflare DNS-over-HTTPS',
      'dns.caa': 'Allowed certificate authorities (CAA)',
      'dns.dnssec': 'DNSSEC',
      'dns.caaNone': 'No CAA record – no issuance restrictions are published.',
      'dns.caaRecord': '{n} record',
      'dns.caaRecords': '{n} records',
      'dns.caaWild': 'wildcard',
      'dns.dnssecOn': 'Enabled · AD = true',
      'dns.dnssecOff': 'Not detected · AD = false',
      'dns.note': 'CAA defines which authority may issue a certificate for the domain. DNSSEC protects DNS answers from tampering.',
      'dns.fail': 'DNS data is unavailable right now. Please try again later.',
      'timeline.title': 'Issuance history',
      'timeline.summary': '{n} issuances in the last 12 months',
      'timeline.summaryOne': '1 issuance in the last 12 months',
      'timeline.issuers': '{n} issuers',
      'timeline.issuersOne': '1 issuer',
      'timeline.note': 'Certificates were issued by several CAs in the past year:',
      'compare.title': 'Apex and www side by side',
      'compare.subtitle': '{apex} and www.{apex}',
      'compare.scan': 'Checking both domains…',
      'compare.valid': 'Valid',
      'compare.expiring': 'Expiring soon',
      'compare.expired': 'Expired',
      'compare.days': '{n} days left',
      'compare.issuer': 'Issuer: {name}',
      'compare.notFound': 'No certificate found in CT logs',
      'compare.failed': 'Check failed',
      'compare.open': 'View detailed result',
      'compare.bothOk': 'Both domains have a valid certificate.',
      'compare.partial': 'At least one domain has a missing or expired certificate.',
      'compare.note': 'Apex and www are separate hosts – a certificate for one may not cover the other. Check both.',
      'f.title': 'Check findings',
      'f.summaryFail': '{n} problems',
      'f.summaryFailOne': '1 problem',
      'f.summaryWarn': '{n} warnings',
      'f.summaryWarnOne': '1 warning',
      'f.summaryOk': 'All checks passed',
      'f.allChecks': 'All checks ({n})',
      'f.hostOk': 'Certificate covers {host}',
      'f.hostOkD': 'The certificate lists {host}, so browsers accept this hostname.',
      'f.hostFail': 'Certificate does not cover {host}',
      'f.hostFailD': 'The certificate does not list {host}. Browsers would show a security warning for this hostname.',
      'f.expiryOk': 'Certificate is valid for another {n} days',
      'f.expiryOkD': 'Renew before {date} to avoid downtime.',
      'f.expiryWarn': 'Certificate expires in {n} days',
      'f.expiryWarnD': 'Renew now – after {date} visitors will see a browser warning.',
      'f.expiryFail': 'Certificate has expired',
      'f.expiryFailD': 'The certificate expired on {date}. Until it is renewed, visitors will see a security warning.',
      'f.validityOk': 'Validity of {n} days is within the limit',
      'f.validityOkD': 'CA/B Forum rule: a publicly trusted certificate must not be valid for more than 398 days.',
      'f.validityWarn': 'Validity of {n} days exceeds the 398-day limit',
      'f.validityWarnD': 'Chrome and Safari may not trust a certificate with such a long lifetime. Reissue with a shorter validity.',
      'f.keyOk': 'Public key: {key}',
      'f.keyOkD': 'Key strength meets current requirements (at least RSA 2048 or EC P-256).',
      'f.keyFail': 'Weak public key: {key}',
      'f.keyFailD': 'RSA keys below 2048 bits are considered insecure. Reissue with an RSA 2048+ or EC P-256 key.',
      'f.keyInfo': 'Public key: {key}',
      'f.keyInfoD': 'The key type could not be determined precisely. Check it with OpenSSL.',
      'f.sigOk': 'Signature algorithm: {alg}',
      'f.sigOkD': 'A secure hash (SHA-256 or stronger) is in use.',
      'f.sigFail': 'Weak signature algorithm: {alg}',
      'f.sigFailD': 'Browsers consider SHA-1 or MD5 signatures insecure. Reissue the certificate with SHA-256.',
      'f.sigInfo': 'Signature algorithm: {alg}',
      'f.sigInfoD': 'Unknown algorithm. Verify the certificate with OpenSSL.',
      'f.revokedFail': 'Certificate has been revoked',
      'f.revokedFailD': 'The issuer has revoked this certificate. Reissue immediately.',
      'f.wildcardInfo': 'Certificate uses a wildcard ({pattern})',
      'f.wildcardInfoD': 'A wildcard covers every subdomain at the same level. Make sure that scope is intended.',
      'f.ctOk': 'Certificate is in CT logs',
      'f.ctOkD': 'The certificate is logged in Certificate Transparency (source: {source}) – Chrome and Safari require this.',
      'f.chainOk': 'Chain contains {n} certificates',
      'f.chainOkD': 'The server sends the leaf and at least one intermediate, so clients can complete the chain.',
      'f.chainMissingWarn': 'Chain contains only the leaf certificate',
      'f.chainMissingWarnD': 'The server does not send an intermediate certificate. Some clients cannot complete the chain. Add the intermediate to the server configuration.',
      'f.chainRootInfo': 'Server also sends the root certificate',
      'f.chainRootInfoD': 'The root is unnecessary and increases the size of every connection. Remove it from the served chain.',
      'f.chainExpiryWarn': 'A chain certificate expires soon: {name}',
      'f.chainExpiryWarnD': 'An intermediate certificate expires on {date}. Contact your CA and update the chain.',
      'f.chainCheckInfo': 'CT log and served leaf differ',
      'f.chainCheckInfoD': 'This can be normal when a domain has several valid certificates (for example behind a CDN). Check the server configuration if it is unexpected.',
      'f.caaOk': 'CAA records are present ({n})',
      'f.caaOkD': 'CAA records restrict which CAs may issue certificates for the domain.',
      'f.caaInfo': 'No CAA records',
      'f.caaInfoD': 'CAA records prevent unauthorised CAs from issuing certificates. Example: issue "letsencrypt.org"',
      'f.dnssecOk': 'DNSSEC is active',
      'f.dnssecOkD': 'DNS answers are cryptographically signed.',
      'f.dnssecInfo': 'DNSSEC is not active',
      'f.dnssecInfoD': 'DNSSEC protects DNS answers against spoofing. Ask your DNS provider for DNSSEC support.',
      'f.headersOk': 'HTTP security header grade: {grade}',
      'f.headersOkD': 'Security headers (HSTS, CSP and others) are well configured.',
      'f.headersInfo': 'HTTP security header grade: {grade}',
      'f.headersInfoD': 'Headers are partially configured. See details in MDN HTTP Observatory.',
      'f.headersWarn': 'HTTP security header grade: {grade}',
      'f.headersWarnD': 'Several security headers are missing or weak. See the recommendations in MDN HTTP Observatory.',
      'f.headersFail': 'HTTP security header grade: {grade}',
      'f.headersFailD': 'Security headers are missing or dangerously configured. Fix HSTS, CSP and X-Content-Type-Options.',
      'sans.title': 'Covered hostnames ({n})',
      'sans.more': 'Show all ({n})',
      'sans.less': 'Show fewer',
      'badge.revoked': 'Revoked',
      'badge.revokedFull': 'The certificate has been revoked by its issuer',
      'advice.valid': 'All good – nothing to do before the next renewal.',
      'advice.expiring': 'Renew the certificate early to avoid an outage.',
      'advice.expired': 'Renew immediately – otherwise browsers may refuse to open the site.',
      'source.note': 'Data: Certificate Transparency logs ({source}) · showing the latest issuance',
      'obs.title': 'Security headers score',
      'obs.score': 'score {score}/100',
      'obs.link': 'View full report',
      'links.ssllabs': 'Deep analysis: SSL Labs',
      'links.crtsh': 'Certificate history: crt.sh',
      'history.title': 'Recent checks',
      'history.clear': 'Clear',
      'features.title': 'Why check your certificate regularly?',
      'feat1.title': 'Visitor trust',
      'feat1.text': 'Browsers show a warning when opening a site with an expired certificate, and visitors leave immediately – taking their trust with them.',
      'feat2.title': 'Search engines',
      'feat2.text': 'HTTPS is a Google ranking factor. A broken certificate drops your site well down the search results, or out of them entirely.',
      'feat3.title': 'Encrypted traffic',
      'feat3.text': 'SSL/TLS encrypts the connection between visitor and server. An expired certificate leaves the data open to interception and tampering.',
      'faq.title': 'Frequently asked questions',
      'faq1.q': 'What does this site do?',
      'faq1.a': 'ssl.ee checks a domain\'s SSL/TLS certificate validity: how long it is valid, who issued it, and which hostnames it protects. Just type a domain name – you get an answer within seconds.',
      'faq2.q': 'Where does the data come from?',
      'faq2.a': 'Certificate data is read from Certificate Transparency logs via Cert Spotter (with crt.sh as backup); the HTTP security-header score comes from MDN HTTP Observatory, the full chain and CT/chain comparison from Trustico SSL Tools, and CAA/DNSSEC from Cloudflare DNS-over-HTTPS. All requests run directly in your browser.',
      'faq3.q': 'Why might the information differ from reality?',
      'faq3.a': 'We show the most recently issued certificate from the CT logs. A server or CDN may sometimes serve a different (e.g. older) certificate – for a full analysis (protocols and ciphers included) use the SSL Labs link below.',
      'faq4.q': 'What does "expiring soon" mean?',
      'faq4.a': 'Less than 30 days remain on the certificate. We recommend renewing right away so the site doesn\'t go dark because a renewal was forgotten.',
      'faq5.q': 'Is it free to use?',
      'faq5.a': 'Yes. ssl.ee is free, requires no sign-up and collects no personal data. The upstream data sources may apply their own rate limits.',
      'footer.tagline': 'A privacy-respecting SSL certificate checker – every query runs in your browser.',
      'footer.sources': 'Data sources: Cert Spotter · crt.sh · MDN HTTP Observatory · Trustico · Cloudflare DNS',
      'footer.navCheck': 'Check a certificate',
      'footer.navLearn': 'Certificate renewal',
      'footer.navFaq': 'Frequently asked questions',
      'footer.navApi': 'API documentation',
    },
  };

  /* ---------- Element refs ---------- */
  const $ = (id) => document.getElementById(id);
  const els = {
    form: $('check-form'), input: $('domain-input'), btn: $('check-btn'),
    compareBtn: $('compare-btn'),
    themeToggle: $('theme-toggle'),
    scan: $('scan-state'), scanHost: $('scan-host'), scanMsg: $('scan-msg'),
    error: $('error-state'), errorMsg: $('error-msg'), errorLinks: $('error-links'),
    card: $('result-card'),
    statusIcon: $('status-icon'), statusTitle: $('status-title'), statusDomain: $('status-domain'),
    statusChip: $('status-chip'), advice: $('advice'),
    gaugeProgress: $('gauge-progress'), gaugeNumber: $('gauge-number'),
    gaugeLabel: $('gauge-label'), gaugeCaption: $('gauge-caption'),
    detailIssuer: $('detail-issuer'), detailFrom: $('detail-from'),
    detailUntil: $('detail-until'), detailFp: $('detail-fp'),
    certDetails: $('cert-details'), certSerial: $('cert-serial'),
    certSubject: $('cert-subject'), certSignature: $('cert-signature'),
    certKey: $('cert-key'), certPem: $('cert-pem'), certKind: $('cert-kind'),
    certChainPem: $('cert-chain-pem'), chainPemNote: $('chain-pem-note'),
    copyPem: $('copy-pem'), copyChain: $('copy-chain'), downloadPem: $('download-pem'),
    downloadChain: $('download-chain'), copyCurl: $('copy-curl'), copyOpenssl: $('copy-openssl'),
    chainStatus: $('chain-status'),
    chainTree: $('chain-tree'), chainTreeList: $('chain-tree-list'),
    chainTreeMeta: $('chain-tree-meta'), chainTreeNote: $('chain-tree-note'),
    chainCheck: $('chain-check'), chainCheckIcon: $('chain-check').querySelector('.chain-check-icon'),
    chainCheckTitle: $('chain-check-title'), chainCheckText: $('chain-check-text'),
    chainCheckFps: $('chain-check-fps'), chainCheckCt: $('chain-check-ct'),
    chainCheckChain: $('chain-check-chain'),
    dnsPanel: $('dns-panel'), dnsCaa: $('dns-caa'), dnsDnssec: $('dns-dnssec'), dnsNote: $('dns-note'),
    timeline: $('timeline'), timelineSummary: $('timeline-summary'),
    timelineTrack: $('timeline-track'), timelineNote: $('timeline-note'),
    comparePanel: $('compare-panel'), compareTitle: $('compare-title'),
    compareSubtitle: $('compare-subtitle'), compareCards: $('compare-cards'),
    compareSummary: $('compare-summary'), compareNote: $('compare-note'),
    findings: $('findings'), findingsSummary: $('findings-summary'),
    findingsList: $('findings-list'), findingsMore: $('findings-more'),
    findingsMoreToggle: $('findings-more-toggle'), findingsRest: $('findings-rest'),
    sanTitle: $('san-title'), sanList: $('san-list'), sanToggle: $('san-toggle'),
    badges: $('badges'),
    obs: $('obs'), obsGrade: $('obs-grade'), obsScore: $('obs-score'), obsLink: $('obs-link'),
    sourceNote: $('source-note'), linkSsllabs: $('link-ssllabs'), linkCrtsh: $('link-crtsh'),
    shareLink: $('share-link'), copyResult: $('copy-result'), addReminder: $('add-reminder'),
    shareStatus: $('share-status'),
    history: $('history'), historyList: $('history-list'), historyClear: $('history-clear'),
    footerYear: $('footer-year'),
  };

  /* ---------- State ---------- */
  let lang = detectLang();
  let history = loadHistory();
  let lastRender = null;   // viimane olek keelevalve jaoks uuesti joonistamiseks
  let checkCounter = 0;    // aegunud asünkroonsete vastuste eiramiseks
  let sansExpanded = false;

  const THEME_KEY = 'ssl-ee-theme';

  function detectTheme() {
    try { return localStorage.getItem(THEME_KEY) === 'light' ? 'light' : 'dark'; }
    catch { return 'dark'; }
  }

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    if (els.themeToggle) {
      els.themeToggle.setAttribute('aria-pressed', String(theme === 'light'));
      els.themeToggle.setAttribute('aria-label', t('nav.theme'));
      els.themeToggle.title = t('nav.theme');
    }
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', theme === 'light' ? '#f5f7fb' : '#04060c');
    try { localStorage.setItem(THEME_KEY, theme); } catch { /* privaatne režiim */ }
  }

  function detectLang() {
    // Keel tuleb URL-ilt: eestikeelne leht on /, ingliskeelne /en/.
    return document.documentElement.lang === 'en' ? 'en' : 'et';
  }

  function t(key, vars) {
    let s = (I18N[lang] && I18N[lang][key]) != null ? I18N[lang][key] : (I18N.et[key] != null ? I18N.et[key] : key);
    if (vars) for (const k of Object.keys(vars)) s = s.split('{' + k + '}').join(String(vars[k]));
    return s;
  }

  function daysText(n) {
    if (lang === 'et') return n === 1 ? '1 päev' : n + ' päeva';
    return n === 1 ? '1 day' : n + ' days';
  }

  function fmtDate(ms) {
    try {
      return new Intl.DateTimeFormat(lang === 'et' ? 'et-EE' : 'en-GB', { year: 'numeric', month: 'long', day: 'numeric' }).format(new Date(ms));
    } catch { return new Date(ms).toISOString().slice(0, 10); }
  }

  function fmtShortDate(ms) {
    try {
      return new Intl.DateTimeFormat(lang === 'et' ? 'et-EE' : 'en-GB', { day: 'numeric', month: 'short', year: '2-digit' }).format(new Date(ms));
    } catch { return new Date(ms).toISOString().slice(0, 10); }
  }

  /* ---------- Minimaalne ASN.1 / X.509 parser (ilma väliste teekideta) ---------- */

  // Levinud OID-id: algoritmid, kõverad ja DN-i atribuudid
  const OIDS = {
    '1.2.840.113549.1.1.1': 'RSA',
    '1.2.840.113549.1.1.5': 'SHA-1 with RSA',
    '1.2.840.113549.1.1.11': 'SHA-256 with RSA',
    '1.2.840.113549.1.1.12': 'SHA-384 with RSA',
    '1.2.840.113549.1.1.13': 'SHA-512 with RSA',
    '1.2.840.10045.4.3.2': 'ECDSA with SHA-256',
    '1.2.840.10045.4.3.3': 'ECDSA with SHA-384',
    '1.2.840.10045.4.3.4': 'ECDSA with SHA-512',
    '1.3.101.112': 'Ed25519',
    '1.3.101.113': 'Ed448',
    '1.2.840.10045.2.1': 'EC public key',
    '1.2.840.10045.3.1.7': 'P-256 (prime256v1)',
    '1.3.132.0.34': 'P-384 (secp384r1)',
    '1.3.132.0.35': 'P-521 (secp521r1)',
    '2.5.4.3': 'CN', '2.5.4.4': 'SN', '2.5.4.5': 'serialNumber',
    '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST',
    '2.5.4.9': 'STREET', '2.5.4.10': 'O', '2.5.4.11': 'OU',
    '2.5.4.97': 'organizationIdentifier',
  };

  function base64ToBytes(b64) {
    try {
      const s = atob(b64);
      const out = new Uint8Array(s.length);
      for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
      return out;
    } catch { return null; }
  }

  function toPem(b64) {
    const lines = String(b64).match(/.{1,64}/g) || [];
    return '-----BEGIN CERTIFICATE-----\n' + lines.join('\n') + '\n-----END CERTIFICATE-----';
  }

  function derReader(bytes) {
    let pos = 0;
    return {
      readTLV() {
        if (pos + 2 > bytes.length) return null;
        const tag = bytes[pos++];
        let len = bytes[pos++];
        if (len & 0x80) {
          const n = len & 0x7f;
          if (n === 0 || n > 4 || pos + n > bytes.length) return null;
          len = 0;
          for (let i = 0; i < n; i++) len = (len << 8) | bytes[pos++];
        }
        if (!Number.isFinite(len) || len < 0 || pos + len > bytes.length) return null;
        const value = bytes.subarray(pos, pos + len);
        pos += len;
        return { tag, value };
      },
    };
  }

  function derOid(value) {
    if (!value || !value.length) return '';
    const nums = [];
    let acc = 0;
    for (const b of value) {
      acc = acc * 128 + (b & 0x7f);
      if ((b & 0x80) === 0) { nums.push(acc); acc = 0; }
    }
    const first = nums.length ? nums.shift() : 0;
    const a = Math.min(Math.floor(first / 40), 2);
    return [a, first - a * 40, ...nums].join('.');
  }

  function derIntHex(value) {
    let hex = '';
    for (const b of value) hex += b.toString(16).padStart(2, '0');
    return hex.replace(/^0+/, '') || '0';
  }

  function derText(tlv) {
    if (!tlv) return '';
    if (tlv.tag === 0x0c && typeof TextDecoder !== 'undefined') {
      try { return new TextDecoder('utf-8').decode(tlv.value); } catch { /* edasi */ }
    }
    let s = '';
    for (const b of tlv.value) s += String.fromCharCode(b);
    return s;
  }

  function parseName(tlv) {
    if (!tlv || tlv.tag !== 0x30) return '–';
    const r = derReader(tlv.value);
    const parts = [];
    let set;
    while ((set = r.readTLV())) {
      if (set.tag !== 0x31) continue;
      const sr = derReader(set.value);
      let attr;
      while ((attr = sr.readTLV())) {
        if (attr.tag !== 0x30) continue;
        const ar = derReader(attr.value);
        const oidTLV = ar.readTLV(), valTLV = ar.readTLV();
        if (!oidTLV || !valTLV) continue;
        const oid = derOid(oidTLV.value);
        parts.push((OIDS[oid] || oid) + '=' + derText(valTLV));
      }
    }
    return parts.length ? parts.join(', ') : '–';
  }

  function parseAlgorithm(tlv) {
    if (!tlv || tlv.tag !== 0x30) return null;
    const r = derReader(tlv.value);
    const oidTLV = r.readTLV();
    if (!oidTLV) return null;
    const oid = derOid(oidTLV.value);
    return { oid, name: OIDS[oid] || oid };
  }

  function bitLength(bytes) {
    let i = 0;
    while (i < bytes.length && bytes[i] === 0) i++;
    if (i >= bytes.length) return 0;
    return (bytes.length - i - 1) * 8 + (32 - Math.clz32(bytes[i]));
  }

  function parseX509(b64) {
    const bytes = base64ToBytes(b64);
    if (!bytes) return null;
    try {
      const cert = derReader(bytes).readTLV();
      if (!cert || cert.tag !== 0x30) return null;
      const cr = derReader(cert.value);
      const tbs = cr.readTLV();
      const sigOuter = cr.readTLV();
      if (!tbs || tbs.tag !== 0x30 || !sigOuter) return null;

      const tr = derReader(tbs.value);
      let tlv = tr.readTLV();
      if (tlv && tlv.tag === 0xa0) tlv = tr.readTLV(); // [0] EXPLICIT version
      const serialTLV = tlv;
      const sigTbs = tr.readTLV();
      const issuerTLV = tr.readTLV();
      tr.readTLV(); // validity
      const subjectTLV = tr.readTLV();
      const spkiTLV = tr.readTLV();

      const sig = parseAlgorithm(sigOuter) || parseAlgorithm(sigTbs);
      let key = '–';
      if (spkiTLV && spkiTLV.tag === 0x30) {
        const sr = derReader(spkiTLV.value);
        const algTLV = sr.readTLV();
        const bitTLV = sr.readTLV();
        const alg = parseAlgorithm(algTLV);
        if (alg) {
          if (alg.oid === '1.2.840.113549.1.1.1') { // RSA
            let bits = 0;
            if (bitTLV && bitTLV.value.length > 1) {
              const kr = derReader(bitTLV.value.subarray(1)); // esimene bait = kasutamata bitid
              const seq = kr.readTLV();                       // RSAPublicKey SEQUENCE
              if (seq && seq.tag === 0x30) {
                const sr = derReader(seq.value);
                const mod = sr.readTLV();                     // modulus INTEGER
                if (mod && mod.tag === 0x02) bits = bitLength(mod.value);
              }
            }
            key = 'RSA' + (bits ? '-' + bits : '');
          } else if (alg.oid === '1.2.840.10045.2.1') { // EC
            const ar = derReader(algTLV.value);
            ar.readTLV();
            const curveTLV = ar.readTLV();
            const curve = curveTLV ? (OIDS[derOid(curveTLV.value)] || derOid(curveTLV.value)) : '';
            key = 'ECDSA' + (curve ? ' · ' + curve : '');
          } else {
            key = alg.name;
          }
        }
      }

      return {
        serial: serialTLV ? derIntHex(serialTLV.value) : '–',
        issuerDn: parseName(issuerTLV),
        subjectDn: parseName(subjectTLV),
        signature: sig ? sig.name : '–',
        key,
      };
    } catch { return null; }
  }

  function buildTimeline(rows) {
    if (!Array.isArray(rows) || !rows.length) return null;
    // queryCrtsh tagastab normaliseeritud read (notBefore/issuer), aga toetame ka
    // crt.sh toorandmeid (not_before/issuer_name), kui varumeetod muutub.
    const items = rows.map((r) => ({
      ts: Number.isFinite(r.notBefore) ? r.notBefore : crtDate(r.not_before),
      issuer: r.issuer || parseCn(r.issuer_name),
    })).filter((x) => Number.isFinite(x.ts));
    if (!items.length) return null;
    items.sort((a, b) => b.ts - a.ts);
    const since = Date.now() - 365 * 864e5;
    const recent = items.filter((x) => x.ts >= since);
    const issuers = [...new Set(recent.map((x) => x.issuer).filter(Boolean))];
    return { recentCount: recent.length, issuers, items: items.slice(0, 6) };
  }

  /* ---------- i18n rakendamine ---------- */
  function applyI18n() {
    document.documentElement.lang = lang;
    document.title = t('meta.title');
    document.querySelectorAll('[data-i18n]').forEach((el) => { el.textContent = t(el.dataset.i18n); });
    document.querySelectorAll('[data-i18n-html]').forEach((el) => { el.innerHTML = t(el.dataset.i18nHtml); });
    document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => { el.placeholder = t(el.dataset.i18nPlaceholder); });
    document.querySelectorAll('[data-i18n-aria-label]').forEach((el) => { el.setAttribute('aria-label', t(el.dataset.i18nAriaLabel)); });
    const et = $('lang-et'), en = $('lang-en');
    if (et) {
      if (lang === 'et') et.setAttribute('aria-current', 'page');
      else et.removeAttribute('aria-current');
    }
    if (en) {
      if (lang === 'en') en.setAttribute('aria-current', 'page');
      else en.removeAttribute('aria-current');
    }
    if (els.themeToggle) {
      els.themeToggle.setAttribute('aria-label', t('nav.theme'));
      els.themeToggle.title = t('nav.theme');
    }
    renderHistory();
    if (lastRender) rerenderDynamic();
  }

  function rerenderDynamic() {
    if (!lastRender) return;
    if (lastRender.type === 'result') renderResult(lastRender.data);
    else if (lastRender.type === 'compare') paintCompare(lastRender.data.apex, lastRender.data.results);
    else if (lastRender.type === 'error') renderError(lastRender.data);
    else if (lastRender.type === 'scan') showScan(lastRender.host, lastRender.msg);
  }

  /* ---------- Abifunktsioonid ---------- */
  function hideStates() {
    els.scan.hidden = true;
    els.error.hidden = true;
    els.card.hidden = true;
    if (els.comparePanel) els.comparePanel.hidden = true;
    showShareStatus('');
  }

  function smoothScroll(el) {
    const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    try { el.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' }); } catch { /* vanemad brauserid */ }
  }

  async function fetchJson(url, opts) {
    const o = opts || {};
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), o.timeout || 15000);
    try {
      const res = await fetch(url, {
        method: o.method || 'GET', headers: o.headers, body: o.body,
        signal: ctrl.signal, cache: 'no-store',
      });
      if (!res.ok) { const e = new Error('HTTP ' + res.status); e.status = res.status; throw e; }
      return await res.json();
    } finally { clearTimeout(timer); }
  }

  function parseCn(dn) {
    if (!dn) return null;
    const parts = String(dn).split(',');
    for (const p of parts) {
      const s = p.trim();
      if (s.toUpperCase().startsWith('CN=')) return s.slice(3).trim();
    }
    return String(dn);
  }

  function crtDate(s) {
    if (!s) return NaN;
    if (/[Zz]$/.test(s) || /[+-]\d{2}:?\d{2}$/.test(s)) return Date.parse(s);
    return Date.parse(s + 'Z'); // crt.sh ajad on UTC, kuid ilma sufiksiteta
  }

  /* ---------- Andmeallikad ---------- */
  function normCs(r) {
    return {
      notBefore: Date.parse(r.not_before),
      notAfter: Date.parse(r.not_after),
      dnsNames: Array.isArray(r.dns_names) ? r.dns_names.map((n) => String(n).toLowerCase()) : [],
      issuer: (r.issuer && (r.issuer.friendly_name || parseCn(r.issuer.name))) || null,
      revoked: r.revoked === true,
      sha256: r.cert_sha256 || null,
      pemData: (r.cert && typeof r.cert.data === 'string') ? r.cert.data : null,
      certType: (r.cert && r.cert.type) || null,
    };
  }

  async function queryCertspotter(host, subdomains) {
    const params = new URLSearchParams({ domain: host, include_subdomains: subdomains ? 'true' : 'false' });
    params.append('expand', 'dns_names');
    params.append('expand', 'issuer');
    params.append('expand', 'cert');
    const rows = await fetchJson(CS_API + '?' + params.toString(), { timeout: CONFIG.timeouts.certspotter });
    if (!Array.isArray(rows)) return [];
    return rows.map(normCs).filter((c) => Number.isFinite(c.notBefore) && Number.isFinite(c.notAfter));
  }

  function normCrtshRows(rows) {
    if (!Array.isArray(rows)) return [];
    return rows.map((r) => ({
      notBefore: crtDate(r.not_before),
      notAfter: crtDate(r.not_after),
      dnsNames: String(r.name_value || '').split(/\r?\n/).map((s) => s.trim().toLowerCase()).filter(Boolean),
      issuer: parseCn(r.issuer_name),
      revoked: false,
      sha256: null,
    })).filter((c) => Number.isFinite(c.notBefore) && Number.isFinite(c.notAfter));
  }

  async function queryCrtsh(host) {
    // crt.sh-l puudub CORS – brauseris töötab ajalugu ainult oma Workeri kaudu.
    // Otsepäring jääb varuks, kui API pole juurutatud või ajutiselt kättesaamatu.
    try {
      const res = await fetchJson(API_BASE + '/history?d=' + encodeURIComponent(host), { timeout: CONFIG.timeouts.crtsh });
      if (res && res.ok && Array.isArray(res.rows)) return normCrtshRows(res.rows);
    } catch { /* edasi otse crt.sh-le */ }
    return normCrtshRows(await fetchJson(CRTSH_API + '?q=' + encodeURIComponent(host) + '&output=json', { timeout: CONFIG.timeouts.crtsh }));
  }

  /* ---------- Sobitamine ja valik ---------- */
  function hostMatches(name, host) {
    if (name === host) return true;
    if (name.startsWith('*.')) {
      const suffix = name.slice(1); // ".example.com"
      return host.endsWith(suffix) && host.length > suffix.length;
    }
    return false;
  }

  function coversHost(entry, host) {
    return entry.dnsNames.some((n) => hostMatches(n, host));
  }

  function pickCert(entries) {
    const seen = new Set();
    const uniq = entries.filter((e) => {
      const k = e.sha256 || (e.issuer + '|' + e.notBefore + '|' + e.notAfter);
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
    const now = Date.now();
    // "aktiivne" = kehtib praegu ja väljaandmine pole tulevikus
    const active = uniq.filter((e) => e.notAfter > now && e.notBefore <= now);
    const pool = active.length ? active : uniq;
    pool.sort((a, b) => b.notBefore - a.notBefore);
    return { cert: pool[0] || null, hasActive: active.length > 0 };
  }

  /* ---------- Domeeni normaliseerimine ---------- */
  function normalizeDomain(raw) {
    if (typeof raw !== 'string') return null;
    let s = raw.trim().toLowerCase();
    if (!s) return null;
    s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, ''); // skeem
    s = s.split('/')[0].split('?')[0].split('#')[0];
    s = s.split(':')[0];                          // port
    s = s.replace(/\.+$/, '');                    // lõpupunktid
    if (!s || s.length > 253) return null;
    let host;
    try { host = new URL('https://' + s).hostname; } catch { return null; }
    if (!host || !host.includes('.') || host === 'localhost') return null;
    if (!/^[a-z0-9.-]+$/.test(host)) return null;
    const re = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
    return re.test(host) ? host : null;
  }

  /* ---------- Kontrolli voog ---------- */
  const ICONS = {
    valid: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9.5"/><path d="M8.5 12.5l2.5 2.5 4.5-5"/></svg>',
    expiring: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3.5l9 16H3l9-16z"/><path d="M12 10v4"/><path d="M12 17.2v.01"/></svg>',
    expired: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9.5"/><path d="M9 9l6 6"/><path d="M15 9l-6 6"/></svg>',
    revoked: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 4.3L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 4.3a2 2 0 0 0-3.4 0z"/><path d="M12 9v4"/><path d="M12 17v.01"/></svg>',
  };

  function showScan(host, msg) {
    hideStates();
    els.scan.hidden = false;
    els.scanHost.textContent = host;
    els.scanMsg.textContent = msg;
    smoothScroll(els.scan);
  }

  function renderError(data) {
    lastRender = { type: 'error', data };
    hideStates();
    els.error.hidden = false;
    const vars = data.vars || (data.host != null ? { host: data.host } : {});
    els.errorMsg.textContent = t('error.' + data.type, vars);
    if (data.host && data.type !== 'invalidDomain') {
      els.errorLinks.hidden = false;
      els.errorLinks.textContent = t('error.links') + ' ';
      const a1 = document.createElement('a');
      a1.href = SSLLABS_URL + encodeURIComponent(data.host);
      a1.target = '_blank'; a1.rel = 'noopener'; a1.textContent = 'SSL Labs';
      const a2 = document.createElement('a');
      a2.href = CRTSH_API + '?q=' + encodeURIComponent(data.host);
      a2.target = '_blank'; a2.rel = 'noopener'; a2.textContent = 'crt.sh';
      els.errorLinks.append(a1, ' · ', a2);
    } else {
      els.errorLinks.hidden = true;
    }
    smoothScroll(els.error);
  }

  function setGauge(frac) {
    const C = 2 * Math.PI * 56;
    els.gaugeProgress.style.strokeDasharray = String(C);
    els.gaugeProgress.style.strokeDashoffset = String(C); // lähtesta
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        els.gaugeProgress.style.strokeDashoffset = String(C * (1 - Math.min(Math.max(frac, 0), 1)));
      });
    });
  }

  function renderSans(dnsNames, host) {
    const names = [...new Set(dnsNames)]
      .sort((a, b) => {
        const rank = (n) => (n === host ? 0 : hostMatches(n, host) ? 1 : 2);
        const d = rank(a) - rank(b);
        return d !== 0 ? d : a.localeCompare(b);
      });
    els.sanTitle.textContent = t('sans.title', { n: names.length });
    els.sanList.textContent = '';
    if (!names.length) { els.sanToggle.hidden = true; return; }

    const render = () => {
      const shown = sansExpanded ? names : names.slice(0, CONFIG.sanPreview);
      els.sanList.textContent = '';
      for (const n of shown) {
        const li = document.createElement('li');
        li.textContent = n;
        if (hostMatches(n, host)) li.className = 'hit';
        els.sanList.appendChild(li);
      }
      if (names.length > CONFIG.sanPreview) {
        els.sanToggle.hidden = false;
        els.sanToggle.textContent = sansExpanded ? t('sans.less') : t('sans.more', { n: names.length });
      } else {
        els.sanToggle.hidden = true;
      }
    };
    render();

    els.sanToggle.onclick = () => { sansExpanded = !sansExpanded; render(); };
  }

  /* ---------- Kontrolli leiud (auditi kokkuvõte) ---------- */

  const FINDING_ORDER = { fail: 0, warn: 1, info: 2, pass: 3 };

  function buildFindings(data) {
    const out = [];
    if (!data || !data.cert) return out;
    const { host, cert: c, source, hasActive } = data;
    const now = Date.now();
    const parsed = data.parsed || null;
    const dnsNames = Array.isArray(c.dnsNames) ? c.dnsNames : [];
    const daysLeft = Math.ceil((c.notAfter - now) / 864e5);
    const status = statusOf(c, hasActive);
    const push = (key, level, vars) => out.push({ key, level, vars: vars || {} });

    // 1) Kas sertifikaat katab päritud hosti
    if (dnsNames.length) {
      if (dnsNames.some((n) => hostMatches(n, host))) push('f.hostOk', 'pass', { host });
      else push('f.hostFail', 'fail', { host });
    }

    // 2) Kehtivusaeg
    if (status === 'expired') {
      push('f.expiryFail', 'fail', { date: fmtDate(c.notAfter) });
    } else if (status === 'expiring') {
      push('f.expiryWarn', 'warn', { n: Math.max(daysLeft, 0), date: fmtDate(c.notAfter) });
    } else {
      push('f.expiryOk', 'pass', { n: daysLeft, date: fmtDate(c.notAfter) });
    }

    // 3) Kehtivusaja pikkus (CA/B Forum: avalik sertifikaat kuni 398 päeva)
    const life = Math.round((c.notAfter - c.notBefore) / 864e5);
    if (Number.isFinite(life) && life > 0) {
      if (life > 398) push('f.validityWarn', 'warn', { n: life });
      else push('f.validityOk', 'pass', { n: life });
    }

    // 4) Avaliku võtme tugevus
    const key = parsed && parsed.key ? String(parsed.key) : '';
    const rsa = /^RSA-(\d+)$/.exec(key);
    if (rsa) {
      if (Number(rsa[1]) < 2048) push('f.keyFail', 'fail', { key });
      else push('f.keyOk', 'pass', { key });
    } else if (/^ECDSA · (P-\d+)/.test(key)) {
      push('f.keyOk', 'pass', { key });
    } else if (key && key !== '–') {
      push('f.keyInfo', 'info', { key });
    }

    // 5) Allkirja algoritm
    const sig = parsed && parsed.signature ? String(parsed.signature) : '';
    if (sig && sig !== '–') {
      if (/\bMD5\b|\bSHA-1\b/i.test(sig)) push('f.sigFail', 'fail', { alg: sig });
      else if (/SHA-2|SHA-3|SHA-256|SHA-384|SHA-512|Ed25519|Ed448/i.test(sig)) push('f.sigOk', 'pass', { alg: sig });
      else push('f.sigInfo', 'info', { alg: sig });
    }

    // 6) Tühistamine
    if (c.revoked) push('f.revokedFail', 'fail', {});

    // 7) Metamärk
    const wild = dnsNames.find((n) => n.startsWith('*.') && hostMatches(n, host));
    if (wild) push('f.wildcardInfo', 'info', { pattern: wild });

    // 8) Certificate Transparency
    if (source) push('f.ctOk', 'pass', { source });

    // 9) Serveri saadetud ahel
    if (Array.isArray(data.chainTree) && data.chainTree.length) {
      const nodes = data.chainTree;
      const selfSigned = (n) => n.subject && n.issuer && n.subject === n.issuer;
      if (nodes.length < 2) push('f.chainMissingWarn', 'warn', {});
      else push('f.chainOk', 'pass', { n: nodes.length });
      if (nodes.some(selfSigned)) push('f.chainRootInfo', 'info', {});
      const expiring = nodes.slice(1).filter((n) => !selfSigned(n) &&
        Number.isFinite(n.notAfter) && n.notAfter - now <= CONFIG.warnDays * 864e5);
      if (expiring.length) {
        push('f.chainExpiryWarn', 'warn', {
          name: expiring[0].subject || '–',
          date: fmtDate(expiring[0].notAfter),
        });
      }
    }

    // 10) CT-logi ja serveri lehe erinevus (nõuandev, mitte tingimata viga)
    if (data.chainCheck && data.chainCheck.kind === 'mismatch') push('f.chainCheckInfo', 'info', {});

    // 11) CAA ja DNSSEC
    if (data.dns) {
      if (Array.isArray(data.dns.caa) && data.dns.caa.length) push('f.caaOk', 'pass', { n: data.dns.caa.length });
      else push('f.caaInfo', 'info', {});
      push(data.dns.ad ? 'f.dnssecOk' : 'f.dnssecInfo', data.dns.ad ? 'pass' : 'info', {});
    }

    // 12) HTTP turvapäiste hinne
    if (data.obs && data.obs.grade) {
      const g = String(data.obs.grade).toUpperCase().charAt(0);
      const level = g === 'A' ? 'pass' : (g === 'B' ? 'info' : (g === 'C' ? 'warn' : 'fail'));
      const keyName = { pass: 'f.headersOk', info: 'f.headersInfo', warn: 'f.headersWarn', fail: 'f.headersFail' }[level];
      push(keyName, level, { grade: data.obs.grade });
    }

    return out.sort((a, b) => FINDING_ORDER[a.level] - FINDING_ORDER[b.level]);
  }

  function findingNode(f) {
    const li = document.createElement('li');
    li.className = 'finding finding-' + f.level;

    const icon = document.createElement('span');
    icon.className = 'finding-icon';
    icon.setAttribute('aria-hidden', 'true');
    icon.innerHTML = f.level === 'fail' ? ICON_X
      : (f.level === 'warn' ? ICON_WARN : (f.level === 'pass' ? ICON_CHECK : ICON_INFO));

    const body = document.createElement('div');
    body.className = 'finding-body';
    const title = document.createElement('p');
    title.className = 'finding-title';
    title.textContent = t(f.key, f.vars);
    const detail = document.createElement('p');
    detail.className = 'finding-detail';
    detail.textContent = t(f.key + 'D', f.vars);
    body.append(title, detail);

    li.append(icon, body);
    return li;
  }

  function renderFindings(data) {
    if (!els.findings) return;
    const all = buildFindings(data);
    if (!all.length) { els.findings.hidden = true; return; }

    const fails = all.filter((f) => f.level === 'fail');
    const warns = all.filter((f) => f.level === 'warn');
    const issues = fails.concat(warns);
    const rest = all.filter((f) => f.level === 'info' || f.level === 'pass');

    const parts = [];
    if (fails.length) parts.push(fails.length === 1 ? t('f.summaryFailOne') : t('f.summaryFail', { n: fails.length }));
    if (warns.length) parts.push(warns.length === 1 ? t('f.summaryWarnOne') : t('f.summaryWarn', { n: warns.length }));
    els.findingsSummary.textContent = parts.length ? parts.join(' · ') : t('f.summaryOk');
    els.findingsSummary.className = 'findings-summary' + (parts.length ? (fails.length ? ' bad' : ' warn') : ' ok');

    els.findingsList.textContent = '';
    for (const f of issues) els.findingsList.appendChild(findingNode(f));
    els.findingsList.hidden = issues.length === 0;

    const wasOpen = els.findingsMore.open;
    els.findingsRest.textContent = '';
    for (const f of rest) els.findingsRest.appendChild(findingNode(f));
    els.findingsMore.hidden = rest.length === 0;
    els.findingsMoreToggle.textContent = t('f.allChecks', { n: rest.length });
    els.findingsMore.open = wasOpen && !els.findingsMore.hidden;

    els.findings.hidden = false;
  }

  function renderResult(data) {
    lastRender = { type: 'result', data };
    hideStates();
    const { host, cert: c, source, hasActive } = data;
    const now = Date.now();

    const daysLeft = Math.ceil((c.notAfter - now) / 864e5);
    const daysSince = Math.floor((now - c.notAfter) / 864e5);
    const status = (!hasActive || c.notAfter < now) ? 'expired' : (daysLeft <= CONFIG.warnDays ? 'expiring' : 'valid');

    els.card.className = 'result-card status-' + status;
    els.statusIcon.innerHTML = ICONS[status];
    els.statusTitle.textContent = t('status.' + status);
    els.statusDomain.textContent = host;

    if (status === 'expired') {
      els.statusChip.textContent = daysSince <= 0 ? t('chip.expiredToday') : t('chip.expiredAgo', { n: daysSince });
    } else {
      els.statusChip.textContent = daysText(Math.max(daysLeft, 0));
    }

    els.advice.textContent = t('advice.' + status);

    // Näidik
    const total = Math.max(c.notAfter - c.notBefore, 1);
    const frac = (c.notAfter - now) / total;
    els.gaugeNumber.textContent = status === 'expired' ? String(Math.max(daysSince, 0)) : String(Math.max(daysLeft, 0));
    els.gaugeLabel.textContent = t('gauge.label');
    els.gaugeCaption.textContent = status === 'expired' ? t('gauge.caption.expired') : t('gauge.caption.valid');
    setGauge(frac);

    // Detailid
    els.detailIssuer.textContent = c.issuer || '–';
    els.detailFrom.textContent = fmtDate(c.notBefore);
    els.detailUntil.textContent = fmtDate(c.notAfter);
    if (c.sha256) {
      const fp = c.sha256.toLowerCase();
      els.detailFp.textContent = fp.slice(0, 16) + '…' + fp.slice(-8);
      els.detailFp.title = fp;
    } else {
      els.detailFp.textContent = '–';
      els.detailFp.title = '';
    }

    const parsed = c.pemData ? parseX509(c.pemData) : null;
    data.parsed = parsed;
    renderSans(c.dnsNames, host);
    renderCertDetails(c, host, parsed);
    renderChainCheck(c, host, data);
    renderChainTree(host, data);
    renderDns(host, data);
    els.addReminder.hidden = status === 'expired';
    renderTimeline(data.timeline || null);
    renderFindings(data);

    // Tühistamise märge
    els.badges.textContent = '';
    if (c.revoked) {
      const b = document.createElement('span');
      b.className = 'badge revoked';
      b.title = t('badge.revokedFull');
      b.innerHTML = ICONS.revoked;
      b.appendChild(document.createTextNode(' ' + t('badge.revoked')));
      els.badges.hidden = false;
      els.badges.appendChild(b);
    } else {
      els.badges.hidden = true;
    }

    // Allikaviide + välised lingid
    els.sourceNote.textContent = t('source.note', { source });
    els.linkSsllabs.href = SSLLABS_URL + encodeURIComponent(host);
    els.linkSsllabs.textContent = t('links.ssllabs');
    els.linkCrtsh.href = CRTSH_API + '?q=' + encodeURIComponent(host);
    els.linkCrtsh.textContent = t('links.crtsh');

    // Observatory (boonus) — varem laetud või puudub
    fillObservatory(data.obs || null);

    els.card.hidden = false;
    smoothScroll(els.card);
  }

  function fillObservatory(d) {
    if (!d || !d.grade) { els.obs.hidden = true; return; }
    els.obsGrade.textContent = d.grade;
    const g = String(d.grade).toUpperCase().charAt(0);
    els.obsGrade.className = g === 'A' ? 'obs-grade' : (g === 'B' ? 'obs-grade g-b' : (g === 'C' ? 'obs-grade g-c' : 'obs-grade g-df'));
    els.obsScore.textContent = t('obs.score', { score: d.score });
    els.obsLink.href = d.details_url || ('https://developer.mozilla.org/observatory/analyze?host=' + encodeURIComponent(d.host || ''));
    els.obsLink.textContent = t('obs.link');
    els.obs.hidden = false;
  }

  async function fetchObservatory(host) {
    if (!CONFIG.observatory) return null;
    try {
      const d = await fetchJson(OBS_API + '?host=' + encodeURIComponent(host), { method: 'POST', timeout: CONFIG.timeouts.observatory });
      if (d && d.grade && typeof d.score === 'number') { d.host = host; return d; }
    } catch { /* boonusfunktsioon, vaiki viga */ }
    return null;
  }

  /* ---------- Jagatav link ja tulemuse kopeerimine ---------- */

  function showShareStatus(msg, isError) {
    els.shareStatus.textContent = msg || '';
    els.shareStatus.className = 'share-status' + (isError ? ' error' : '');
    els.shareStatus.hidden = !msg;
  }

  function shareUrl(host) {
    return location.origin + location.pathname + '?d=' + encodeURIComponent(host);
  }

  function buildResultText(data) {
    const { host, cert: c, source, hasActive } = data;
    const now = Date.now();
    const daysLeft = Math.ceil((c.notAfter - now) / 864e5);
    const daysSince = Math.floor((now - c.notAfter) / 864e5);
    const status = (!hasActive || c.notAfter < now) ? 'expired'
      : (daysLeft <= CONFIG.warnDays ? 'expiring' : 'valid');
    const statusLine = status === 'expired'
      ? (daysSince <= 0 ? t('chip.expiredToday') : t('chip.expiredAgo', { n: daysSince }))
      : t('status.' + status) + ' — ' + daysText(Math.max(daysLeft, 0)) + ' ' + t('gauge.caption.valid');
    const names = Array.isArray(c.dnsNames) ? c.dnsNames : [];
    const sans = names.slice(0, 12).join(', ') + (names.length > 12 ? '…' : '');
    const fp = c.sha256 ? c.sha256.toLowerCase() : '–';
    return [
      t('share.title') + ': ' + host,
      '',
      statusLine,
      t('detail.issuer') + ': ' + (c.issuer || '–'),
      t('detail.validFrom') + ': ' + fmtDate(c.notBefore),
      t('detail.validUntil') + ': ' + fmtDate(c.notAfter),
      t('share.sans') + ': ' + (sans || '–'),
      t('detail.fingerprint') + ': ' + fp,
      t('share.source') + ': ' + (source || '–'),
      '',
      shareUrl(host),
    ].join('\n');
  }

  async function copyShareLink(host) {
    if (!host) return;
    const url = shareUrl(host);
    if (navigator.share) {
      try {
        await navigator.share({ title: t('share.title'), url });
        showShareStatus(t('share.linkCopied'));
        return;
      } catch (e) {
        if (e && (e.name === 'AbortError' || e.name === 'Cancel')) return; // kasutaja loobus
        // muu viga → kopeerime lingi ise
      }
    }
    const ok = await copyText(url);
    showShareStatus(t(ok ? 'share.linkCopied' : 'certdetails.copyFail'), !ok);
  }

  async function copyCurrentResult() {
    if (!lastRender || lastRender.type !== 'result') return;
    const ok = await copyText(buildResultText(lastRender.data));
    showShareStatus(t(ok ? 'share.resultCopied' : 'certdetails.copyFail'), !ok);
  }

  /* ---------- curl / OpenSSL käsud ---------- */

  function curlCommand(host) {
    return 'curl -fsSL "' + API_BASE + '/pem?d=' + encodeURIComponent(host) + '" -o ' + host + '.pem';
  }

  function opensslCommand(host) {
    return 'curl -fsSL "' + API_BASE + '/pem?d=' + encodeURIComponent(host) +
      '" | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256';
  }

  async function copyCommand(kind) {
    const data = lastRender && lastRender.type === 'result' ? lastRender.data : null;
    if (!data || !data.host) return;
    const cmd = kind === 'curl' ? curlCommand(data.host) : opensslCommand(data.host);
    const ok = await copyText(cmd);
    showShareStatus(t(ok ? 'cmd.' + kind + 'Copied' : 'certdetails.copyFail'), !ok);
  }

  function renderCertDetails(cert, host, parsedArg) {
    const parsed = parsedArg || (cert.pemData ? parseX509(cert.pemData) : null);
    if (!parsed) { els.certDetails.hidden = true; return; }
    els.certSerial.textContent = parsed.serial;
    els.certSubject.textContent = parsed.subjectDn;
    els.certSignature.textContent = parsed.signature;
    els.certKey.textContent = parsed.key;
    els.certPem.textContent = toPem(cert.pemData);
    els.certKind.textContent = cert.certType === 'precert' ? t('certdetails.precert') : '';
    els.copyPem.textContent = t('certdetails.copy');
    els.copyChain.textContent = t('certdetails.copyChain');
    els.downloadChain.title = t('certdetails.chainNote');
    showChainStatus('');
    els.certDetails.hidden = false;

    // Täielik ahel paremal poolel – laaditakse taustal, ei blokeeri põhitulemust
    els.certChainPem.textContent = t('certdetails.chainLoading');
    els.chainPemNote.hidden = true;
    loadChain(host).then((pems) => {
      // Iguaegne tulemus: ära kirjuta vana domeeni andmeid uue peale
      if (!lastRender || lastRender.type !== 'result' || lastRender.data.host !== host) return;
      if (pems && pems.length) {
        els.certChainPem.textContent = pems.join('\n');
        els.chainPemNote.textContent = t('certdetails.chainNote');
      } else {
        els.certChainPem.textContent = '';
        els.chainPemNote.textContent = t('certdetails.chainLoadFail');
      }
      els.chainPemNote.hidden = false;
    });
  }

  function showChainStatus(msg, kind) {
    els.chainStatus.textContent = msg || '';
    els.chainStatus.className = 'chain-status' + (kind ? ' ' + kind : '');
    els.chainStatus.hidden = !msg;
  }

  function normalizeFp(fp) {
    return typeof fp === 'string' ? fp.replace(/[\s:]/g, '').toLowerCase() : null;
  }

  function nameCn(obj) {
    if (!obj || typeof obj !== 'object') return '';
    return obj.commonName || obj.organizationName || obj.organizationalUnitName || obj.countryName || '';
  }

  async function fetchChainData(host) {
    const d = await fetchJson(CHAIN_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://' + host }),
      timeout: CONFIG.timeouts.chain,
    });
    if (!d || d.success !== true) return null;
    const chain = d.data && d.data.chain;
    if (!Array.isArray(chain)) return null;

    // Trustico tagastab depth=0 lehena — järjestame kindluse mõttes uuesti
    const entries = chain.slice().sort((a, b) =>
      (Number(a && a.depth) || 0) - (Number(b && b.depth) || 0));
    const pems = entries
      .map((x) => x && x.certificate)
      .filter((p) => typeof p === 'string' && p.indexOf('BEGIN CERTIFICATE') !== -1);
    if (!pems.length) return null;

    const last = entries.length - 1;
    const nodes = entries.map((x, i) => {
      const info = (x && x.info) || {};
      const nb = Date.parse(info.notBefore);
      const na = Date.parse(info.notAfter);
      return {
        depth: Number(x && x.depth) || 0,
        role: i === 0 ? 'leaf' : ((x && x.isTrustAnchor) || i === last ? 'root' : 'intermediate'),
        subject: nameCn(info.subject) || '–',
        issuer: nameCn(info.issuer) || '–',
        notBefore: Number.isFinite(nb) ? nb : null,
        notAfter: Number.isFinite(na) ? na : null,
        fp: info.fingerprints ? normalizeFp(info.fingerprints.sha256) : null,
      };
    });

    const leaf = entries[0];
    const info = leaf && leaf.info;
    const leafFp = info && info.fingerprints && normalizeFp(info.fingerprints.sha256);
    return { pems, leafFp, nodes };
  }

  // Kord laaditud ahelat kasutatakse uuesti kuvamisel, kopeerimisel, allalaadimisel ja võrdlusel
  const chainCache = new Map();

  function loadChainData(host) {
    if (!host) return Promise.resolve(null);
    if (chainCache.has(host)) return chainCache.get(host);
    const p = (CONFIG.chain ? fetchChainData(host) : Promise.resolve(null))
      .then((d) => (d && d.pems && d.pems.length ? d : null))
      .catch(() => null);
    chainCache.set(host, p);
    return p;
  }

  function loadChain(host) {
    return loadChainData(host).then((d) => (d ? d.pems : null));
  }

  /* ---------- CT logi leht vs serveri saadetud leht ---------- */

  const ICON_CHECK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 4v5c0 4.4-3.4 8.5-8 9-4.6-.5-8-4.6-8-9V7l8-4z"/><path d="M9 12l2 2 4-4"/></svg>';
  const ICON_WARN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 4.3L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 4.3a2 2 0 0 0-3.4 0z"/><path d="M12 9v4"/><path d="M12 17v.01"/></svg>';
  const ICON_INFO = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><path d="M12 8v.01"/></svg>';
  const ICON_X = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M15 9l-6 6"/><path d="M9 9l6 6"/></svg>';

  function pemToDer(pem) {
    const m = String(pem).match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/);
    return m ? base64ToBytes(m[1].replace(/\s+/g, '')) : null;
  }

  async function sha256Hex(bytes) {
    if (!bytes || !globalThis.crypto || !crypto.subtle) return null;
    try {
      const buf = await crypto.subtle.digest('SHA-256', bytes);
      return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
    } catch { return null; }
  }

  async function compareChain(cert, host) {
    const chain = await loadChainData(host);
    if (!chain) return { kind: 'unknown' };
    if (!cert || !cert.sha256) return { kind: 'noFp' };

    const ct = normalizeFp(cert.sha256);
    // Trustico annab sõrmejälje kaasa; varumeetodina arvutame selle PEM-ist
    const served = chain.leafFp || await sha256Hex(pemToDer(chain.pems[0]));
    if (!ct || !served) return { kind: 'unknown' };
    const leaf = normalizeFp(served);
    return { kind: ct === leaf ? 'ok' : 'mismatch', ct, chain: leaf };
  }

  function paintChainCheck(res) {
    if (!res) { els.chainCheck.hidden = true; return; }
    els.chainCheck.className = 'chain-check kind-' + res.kind;
    els.chainCheckIcon.innerHTML = res.kind === 'mismatch' ? ICON_WARN
      : (res.kind === 'ok' ? ICON_CHECK : ICON_INFO);
    els.chainCheckTitle.textContent = t('chaincheck.title');
    els.chainCheckText.textContent = t('chaincheck.' + res.kind) +
      (res.kind === 'mismatch' ? ' ' + t('chaincheck.note') : '');
    if (res.ct && res.chain) {
      els.chainCheckCt.textContent = t('chaincheck.ctFp', { fp: res.ct });
      els.chainCheckChain.textContent = t('chaincheck.chainFp', { fp: res.chain });
      els.chainCheckFps.hidden = false;
    } else {
      els.chainCheckFps.hidden = true;
    }
    els.chainCheck.hidden = false;
  }

  function renderChainCheck(cert, host, data) {
    if (data.chainCheck !== undefined) { paintChainCheck(data.chainCheck); return; }
    els.chainCheck.hidden = true;
    if (!CONFIG.chain || !host) return;
    compareChain(cert, host).then((res) => {
      if (!lastRender || lastRender.type !== 'result' || lastRender.data.host !== host) return;
      data.chainCheck = res;
      paintChainCheck(res);
      renderFindings(data);
    });
  }

  /* ---------- Sertifikaadiahela puu ---------- */

  function paintChainTree(nodes) {
    if (!nodes || !nodes.length) { els.chainTree.hidden = true; return; }
    els.chainTreeList.textContent = '';
    const now = Date.now();
    for (const node of nodes) {
      const li = document.createElement('li');
      const expired = Number.isFinite(node.notAfter) && node.notAfter < now;
      li.className = 'chain-node' + (node.role === 'root' ? ' is-root' : '') + (expired ? ' expired' : '');

      const top = document.createElement('div');
      top.className = 'chain-node-top';
      const role = document.createElement('span');
      role.className = 'chain-role';
      role.textContent = t('chainTree.' + node.role);
      const depth = document.createElement('span');
      depth.className = 'chain-depth';
      depth.textContent = t('chainTree.depth', { n: node.depth });
      top.append(role, depth);

      const subject = document.createElement('p');
      subject.className = 'chain-subject';
      subject.textContent = node.subject;

      const issuer = document.createElement('p');
      issuer.className = 'chain-issuer';
      issuer.textContent = t('chainTree.issuedBy', { name: node.issuer });

      const valid = document.createElement('p');
      valid.className = 'chain-valid';
      if (Number.isFinite(node.notAfter)) {
        const label = document.createElement('span');
        label.textContent = t('chainTree.validUntil', { date: '' }).trim() + ': ';
        const date = document.createElement('strong');
        date.textContent = fmtDate(node.notAfter);
        valid.append(label, date);
        const days = Math.ceil((node.notAfter - now) / 864e5);
        if (days < 0) valid.append(document.createTextNode(' · ' + t('chainTree.expired')));
        else if (days <= CONFIG.warnDays) valid.append(document.createTextNode(' · ' + t('chainTree.expiring', { n: days })));
      } else {
        const unknown = document.createElement('strong');
        unknown.textContent = '–';
        valid.appendChild(unknown);
      }

      const fp = document.createElement('p');
      fp.className = 'chain-fp';
      fp.textContent = node.fp ? 'SHA-256 · ' + node.fp.slice(0, 24) + '…' : '';
      fp.hidden = !node.fp;

      li.append(top, subject, issuer, valid, fp);
      els.chainTreeList.appendChild(li);
    }
    els.chainTreeMeta.textContent = t('chainTree.count', { n: nodes.length });
    els.chainTreeNote.textContent = t('chainTree.note');
    els.chainTreeNote.hidden = false;
    els.chainTree.hidden = false;
  }

  function renderChainTree(host, data) {
    if (data.chainTree !== undefined) { paintChainTree(data.chainTree); return; }
    els.chainTree.hidden = true;
    if (!CONFIG.chain || !host) return;
    els.chainTreeList.textContent = '';
    els.chainTreeMeta.textContent = t('chainTree.loading');
    els.chainTreeNote.hidden = true;
    els.chainTree.hidden = false;
    loadChainData(host).then((d) => {
      if (!lastRender || lastRender.type !== 'result' || lastRender.data.host !== host) return;
      const nodes = d && d.nodes && d.nodes.length ? d.nodes : null;
      data.chainTree = nodes;
      if (!nodes) { els.chainTree.hidden = true; return; }
      paintChainTree(nodes);
      renderFindings(data);
    });
  }

  /* ---------- CAA ja DNSSEC (Cloudflare DNS-over-HTTPS) ---------- */

  function parseCaaRecord(data) {
    const m = String(data).match(/^\s*(\d+)\s+([a-z0-9-]+)\s+"([\s\S]*)"\s*$/i);
    if (!m) return null;
    return { flags: Number(m[1]), tag: m[2].toLowerCase(), value: m[3] };
  }

  async function queryDns(host) {
    const url = DNS_API + '?name=' + encodeURIComponent(host) + '&type=CAA';
    const d = await fetchJson(url, {
      headers: { Accept: 'application/dns-json' },
      timeout: CONFIG.timeouts.dns,
    });
    if (!d || typeof d !== 'object') return null;

    const seen = new Set();
    const caa = (Array.isArray(d.Answer) ? d.Answer : [])
      .filter((a) => a && Number(a.type) === 257 && typeof a.data === 'string')
      .map((a) => parseCaaRecord(a.data))
      .filter((r) => {
        if (!r) return false;
        const key = r.tag + '|' + r.value;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });

    // AD = Authentic Data: Cloudflare on DNSSEC-i ahelat kontrollinud
    return { caa, ad: d.AD === true, status: d.Status };
  }

  const dnsCache = new Map();

  function loadDns(host) {
    if (!host) return Promise.resolve(null);
    if (dnsCache.has(host)) return dnsCache.get(host);
    const p = (CONFIG.dns ? queryDns(host) : Promise.resolve(null)).catch(() => null);
    dnsCache.set(host, p);
    return p;
  }

  function paintDns(res) {
    if (!res) { els.dnsPanel.hidden = true; return; }
    els.dnsCaa.textContent = '';
    if (!res.caa.length) {
      els.dnsCaa.textContent = t('dns.caaNone');
    } else {
      for (const c of res.caa) {
        const chip = document.createElement('span');
        chip.className = 'dns-chip' + (c.tag === 'issuewild' ? ' wild' : '');
        chip.textContent = c.tag + ': ' + c.value;
        els.dnsCaa.appendChild(chip);
      }
      const count = document.createElement('span');
      count.className = 'dns-count';
      const n = res.caa.length;
      count.textContent = '· ' + t(n === 1 ? 'dns.caaRecord' : 'dns.caaRecords', { n });
      els.dnsCaa.appendChild(count);
    }
    els.dnsDnssec.textContent = '';
    const state = document.createElement('span');
    state.className = res.ad ? 'dns-yes' : 'dns-no';
    state.textContent = t(res.ad ? 'dns.dnssecOn' : 'dns.dnssecOff');
    els.dnsDnssec.appendChild(state);
    els.dnsNote.textContent = t('dns.note');
    els.dnsNote.hidden = false;
    els.dnsPanel.hidden = false;
  }

  function renderDns(host, data) {
    if (data.dns !== undefined) { paintDns(data.dns); return; }
    els.dnsPanel.hidden = true;
    if (!CONFIG.dns || !host) return;
    loadDns(host).then((res) => {
      if (!lastRender || lastRender.type !== 'result' || lastRender.data.host !== host) return;
      data.dns = res;
      paintDns(res);
      renderFindings(data);
    });
  }

  async function copyText(text) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        return true;
      }
      throw new Error('clipboard unavailable');
    } catch {
      // Varumeetod: ajutine tekstiväli, et kopeerimine töötaks ka HTTP-lehel
      try {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        const ok = document.execCommand('copy');
        ta.remove();
        return ok;
      } catch { return false; }
    }
  }

  function saveTextFile(text, filename, mime) {
    const blob = new Blob([text], { type: mime || 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  }

  function savePemFile(text, filename) {
    saveTextFile(text.replace(/\s+$/, '') + '\n', filename, 'application/x-pem-file');
  }

  /* ---------- .ics meeldetuletus ---------- */

  function icsStamp(ms) {
    // toISOString() annab juba Z-liite (nt 2026-11-17T23:34:29.123Z) — ära lisa teist
    return new Date(ms).toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  }

  function icsEscape(s) {
    return String(s).replace(/\\/g, '\\\\').replace(/;/g, '\\;')
      .replace(/,/g, '\\,').replace(/\r?\n/g, '\\n');
  }

  // RFC 5545: pikad read tuleb murda 75 okteti juures, jätkurea algab tühikuga
  function icsFold(line) {
    let total = 0;
    for (const ch of line) {
      const c = ch.codePointAt(0);
      total += c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4;
    }
    if (total <= 75) return line;

    const out = [];
    let cur = '', budget = 75;
    for (const ch of line) {
      const c = ch.codePointAt(0);
      const size = c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4;
      if (size > budget) { out.push(cur); cur = ' '; budget = 74; }
      cur += ch;
      budget -= size;
    }
    out.push(cur);
    return out.join('\r\n');
  }

  function buildIcs(host, notAfter) {
    const start = notAfter - CONFIG.reminderDays * 864e5;
    const end = start + 15 * 60e3;
    const uid = (globalThis.crypto && crypto.randomUUID)
      ? crypto.randomUUID() : Date.now() + '-' + host + '@ssl.ee';
    const lines = [
      'BEGIN:VCALENDAR',
      'VERSION:2.0',
      'PRODID:-//ssl.ee//SSL Certificate Reminder//ET',
      'CALSCALE:GREGORIAN',
      'METHOD:PUBLISH',
      'BEGIN:VEVENT',
      'UID:' + uid,
      'DTSTAMP:' + icsStamp(Date.now()),
      'DTSTART:' + icsStamp(start),
      'DTEND:' + icsStamp(end),
      'SUMMARY:' + icsEscape(t('reminder.title', { host })),
      'DESCRIPTION:' + icsEscape(t('reminder.desc', { host, date: fmtDate(notAfter) })),
      'BEGIN:VALARM',
      'TRIGGER:-PT15M',
      'ACTION:DISPLAY',
      'DESCRIPTION:' + icsEscape(t('reminder.alarm', { host })),
      'END:VALARM',
      'END:VEVENT',
      'END:VCALENDAR',
    ];
    return lines.map(icsFold).join('\r\n') + '\r\n';
  }

  function downloadReminder() {
    const data = lastRender && lastRender.type === 'result' ? lastRender.data : null;
    if (!data || !data.cert || !Number.isFinite(data.cert.notAfter)) return;
    saveTextFile(buildIcs(data.host, data.cert.notAfter),
      data.host + '-ssl-reminder.ics', 'text/calendar;charset=utf-8');
    showShareStatus(t('reminder.ok'));
  }

  function downloadSinglePem(host) {
    const text = els.certPem.textContent;
    if (!text) return;
    savePemFile(text, (host || 'certificate') + '.pem');
    showChainStatus(t('certdetails.pemOk'), 'ok');
  }

  async function copyChain(host) {
    if (!CONFIG.chain || !host) return;
    els.copyChain.disabled = true;
    showChainStatus(t('certdetails.copyingChain'));
    try {
      const pems = await loadChain(host);
      if (!pems) throw new Error('chain unavailable');
      if (!await copyText(pems.join('\n'))) throw new Error('copy failed');
      els.copyChain.textContent = t('certdetails.copied');
      setTimeout(() => { els.copyChain.textContent = t('certdetails.copyChain'); }, 1800);
      showChainStatus(t('certdetails.chainCopied', { n: pems.length }), 'ok');
    } catch {
      showChainStatus(t('certdetails.chainFail'), 'error');
    } finally {
      els.copyChain.disabled = false;
    }
  }

  async function downloadChain(host) {
    if (!CONFIG.chain || !host) return;
    els.downloadChain.disabled = true;
    showChainStatus(t('certdetails.downloading'));
    try {
      const pems = await loadChain(host);
      if (!pems) throw new Error('chain unavailable');
      savePemFile(pems.join('\n'), host + '-full-chain.pem');
      showChainStatus(t('certdetails.chainOk', { n: pems.length }), 'ok');
    } catch {
      showChainStatus(t('certdetails.chainFail'), 'error');
    } finally {
      els.downloadChain.disabled = false;
    }
  }

  function renderTimeline(tl) {
    if (!tl || !tl.items.length) { els.timeline.hidden = true; return; }
    els.timelineSummary.textContent =
      (tl.recentCount === 1 ? t('timeline.summaryOne') : t('timeline.summary', { n: tl.recentCount })) +
      (tl.issuers.length === 1 ? ' · ' + t('timeline.issuersOne')
        : tl.issuers.length > 1 ? ' · ' + t('timeline.issuers', { n: tl.issuers.length }) : '');
    els.timelineTrack.textContent = '';
    for (const item of tl.items) {
      const point = document.createElement('div');
      point.className = 'timeline-point';
      const dot = document.createElement('span');
      dot.className = 'timeline-dot';
      const date = document.createElement('span');
      date.className = 'timeline-date';
      date.textContent = fmtShortDate(item.ts);
      const issuer = document.createElement('span');
      issuer.className = 'timeline-issuer';
      issuer.textContent = item.issuer || '–';
      issuer.title = item.issuer || '';
      point.append(dot, date, issuer);
      els.timelineTrack.appendChild(point);
    }
    if (tl.issuers.length > 1) {
      els.timelineNote.textContent = t('timeline.note') + ' ' + tl.issuers.join(', ');
      els.timelineNote.hidden = false;
    } else {
      els.timelineNote.hidden = true;
    }
    els.timeline.hidden = false;
  }

  /* ---------- Ajalugu ---------- */
  function loadHistory() {
    try {
      const raw = localStorage.getItem('ssl-ee-history');
      const arr = raw ? JSON.parse(raw) : [];
      return Array.isArray(arr) ? arr.slice(0, CONFIG.historyMax) : [];
    } catch { return []; }
  }

  function saveHistory() {
    try { localStorage.setItem('ssl-ee-history', JSON.stringify(history.slice(0, CONFIG.historyMax))); } catch { /* privaatrežiim */ }
  }

  function addHistory(host, status, days) {
    history = history.filter((h) => h.host !== host);
    history.unshift({ host, status, days, ts: Date.now() });
    history = history.slice(0, CONFIG.historyMax);
    saveHistory();
    renderHistory();
  }

  function renderHistory() {
    if (!history.length) { els.history.hidden = true; return; }
    els.history.hidden = false;
    els.historyList.textContent = '';
    const colors = { valid: 'var(--green)', expiring: 'var(--amber)', expired: 'var(--red)' };
    for (const h of history) {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'history-item';
      b.title = h.status === 'expired' ? t('status.expired') : (h.status === 'expiring' ? t('status.expiring') : t('status.valid'));
      const dot = document.createElement('span');
      dot.className = 'history-dot';
      dot.style.background = colors[h.status] || 'var(--muted)';
      b.appendChild(dot);
      b.appendChild(document.createTextNode(h.host));
      b.addEventListener('click', () => { els.input.value = h.host; runCheck(h.host); });
      els.historyList.appendChild(b);
    }
  }

  /* ---------- Peamine voog ---------- */

  // Ühine andmehankimine: ühe domeeni tulemus ja apex+www võrdlus kasutavad sama loogikat
  async function loadDomain(host, opts) {
    const o = opts || {};

    // crt.sh (nüüd oma Workeri kaudu) käib algusest paralleelselt – ajatelg ja varuallikas
    const crtshPromise = queryCrtsh(host)
      .then((rows) => ({ ok: true, rows }))
      .catch(() => ({ ok: false, rows: [] }));

    let entries = null;
    let source = null;
    let anySuccess = false;

    // 1) Cert Spotter — täpne vaste
    try {
      const rows = await queryCertspotter(host, false);
      anySuccess = true;
      if (rows.length) { entries = rows; source = 'Cert Spotter'; }
    } catch { /* edasi */ }
    if (o.stale && o.stale()) return null;

    // 2) Cert Spotter — koos alamdomeenidega, filtreerime hosti katvad
    if (!entries) {
      try {
        const rows = await queryCertspotter(host, true);
        anySuccess = true;
        const filtered = rows.filter((e) => coversHost(e, host));
        if (filtered.length) { entries = filtered; source = 'Cert Spotter'; }
      } catch { /* edasi */ }
      if (o.stale && o.stale()) return null;
    }

    // 3) crt.sh varuallikas (juba käivitatud paralleelpäring)
    if (!entries) {
      if (o.onFallback) o.onFallback();
      const crt = await crtshPromise;
      if (o.stale && o.stale()) return null;
      if (crt.ok) {
        anySuccess = true;
        if (crt.rows.length) { entries = crt.rows; source = 'crt.sh'; }
      }
    }

    return { entries, source, anySuccess, crtshPromise };
  }

  async function runCheck(rawInput) {
    const host = normalizeDomain(rawInput);
    if (!host) {
      renderError({ type: 'invalidDomain' });
      els.input.focus();
      return;
    }

    const checkId = ++checkCounter;
    const stale = () => checkId !== checkCounter;
    sansExpanded = false;
    els.btn.disabled = true;

    showScan(host, t('scan.ct'));

    const loaded = await loadDomain(host, { stale, onFallback: () => showScan(host, t('scan.fallback')) });
    if (stale() || !loaded) { els.btn.disabled = false; return; }
    const { entries, source, anySuccess, crtshPromise } = loaded;

    // HTTP turvapäiste skoor (ei blokeeri põhitulemust)
    const obsPromise = fetchObservatory(host);

    if (!anySuccess) {
      renderError({ type: 'failed', host });
    } else if (!entries || !entries.length) {
      renderError({ type: 'notFound', host });
    } else {
      const picked = pickCert(entries);
      if (!picked.cert) {
        renderError({ type: 'notFound', host });
      } else {
        const data = { host, cert: picked.cert, hasActive: picked.hasActive, source, obs: null, timeline: null };
        renderResult(data);
        addHistory(host, statusOf(picked.cert, picked.hasActive), daysLeftOf(picked.cert));
        obsPromise.then((d) => {
          if (stale()) return;
          data.obs = d;
          if (lastRender && lastRender.type === 'result' && lastRender.data.host === host) {
            fillObservatory(d);
            renderFindings(data);
          }
        });
        crtshPromise.then((crt) => {
          if (stale() || !crt.ok) return;
          data.timeline = buildTimeline(crt.rows);
          if (lastRender && lastRender.type === 'result' && lastRender.data.host === host) renderTimeline(data.timeline);
        });
      }
    }
    els.btn.disabled = false;
  }

  /* ---------- Apex + www kõrvuti ---------- */

  async function runCompare(rawInput) {
    const host = normalizeDomain(rawInput);
    if (!host) {
      renderError({ type: 'invalidDomain' });
      els.input.focus();
      return;
    }

    // Kui sisestati www.variant, võtame aluseks apex-domeeni
    const apex = host.startsWith('www.') ? host.slice(4) : host;
    const hosts = [apex, 'www.' + apex];

    const checkId = ++checkCounter;
    const stale = () => checkId !== checkCounter;
    els.btn.disabled = true;
    if (els.compareBtn) els.compareBtn.disabled = true;
    showScan(hosts.join(' + '), t('compare.scan'));

    const results = await Promise.all(hosts.map(async (h) => {
      try {
        const loaded = await loadDomain(h);
        if (!loaded || !loaded.anySuccess) return { host: h, error: 'failed' };
        if (!loaded.entries || !loaded.entries.length) return { host: h, error: 'notFound' };
        const picked = pickCert(loaded.entries);
        if (!picked.cert) return { host: h, error: 'notFound' };
        return { host: h, cert: picked.cert, hasActive: picked.hasActive, source: loaded.source };
      } catch { return { host: h, error: 'failed' }; }
    }));

    if (stale()) {
      els.btn.disabled = false;
      if (els.compareBtn) els.compareBtn.disabled = false;
      return;
    }

    lastRender = { type: 'compare', data: { apex, results } };
    paintCompare(apex, results);
    els.btn.disabled = false;
    if (els.compareBtn) els.compareBtn.disabled = false;
  }

  function paintCompare(apex, results) {
    hideStates();
    els.compareTitle.textContent = t('compare.title');
    els.compareSubtitle.textContent = t('compare.subtitle', { apex });

    const allValid = results.length === 2 && results.every((r) => !r.error && statusOf(r.cert, r.hasActive) === 'valid');
    els.compareSummary.textContent = t(allValid ? 'compare.bothOk' : 'compare.partial');
    els.compareSummary.className = 'compare-summary ' + (allValid ? 'ok' : 'warn');

    els.compareCards.textContent = '';
    for (const r of results) {
      const status = r.error ? 'error' : statusOf(r.cert, r.hasActive);
      const card = document.createElement('div');
      card.className = 'compare-card status-' + status;

      const head = document.createElement('div');
      head.className = 'compare-card-head';
      const host = document.createElement('strong');
      host.className = 'compare-host';
      host.textContent = r.host;
      const badge = document.createElement('span');
      badge.className = 'compare-badge';
      badge.textContent = r.error ? t('compare.' + r.error) : t('compare.' + status);
      head.append(host, badge);

      const metric = document.createElement('p');
      metric.className = 'compare-metric';
      if (r.error) metric.textContent = '–';
      else if (status === 'expired') metric.textContent = t('compare.expired');
      else metric.textContent = t('compare.days', { n: daysLeftOf(r.cert) });

      const issuer = document.createElement('p');
      issuer.className = 'compare-issuer';
      issuer.textContent = r.error ? '' : t('compare.issuer', { name: r.cert.issuer || '–' });

      const open = document.createElement('button');
      open.type = 'button';
      open.className = 'compare-open';
      open.textContent = t('compare.open');
      open.addEventListener('click', () => { els.input.value = r.host; runCheck(r.host); });

      card.append(head, metric, issuer, open);
      els.compareCards.appendChild(card);
    }

    els.compareNote.textContent = t('compare.note');
    els.comparePanel.hidden = false;
    smoothScroll(els.comparePanel);
  }

  function statusOf(cert, hasActive) {
    const now = Date.now();
    if (!hasActive || cert.notAfter < now) return 'expired';
    return daysLeftOf(cert) <= CONFIG.warnDays ? 'expiring' : 'valid';
  }

  function daysLeftOf(cert) {
    return Math.max(Math.ceil((cert.notAfter - Date.now()) / 864e5), 0);
  }

  /* ---------- Sündmused ---------- */
  els.form.addEventListener('submit', (e) => { e.preventDefault(); runCheck(els.input.value); });

  if (els.compareBtn) els.compareBtn.addEventListener('click', () => runCompare(els.input.value));

  document.querySelectorAll('.chip[data-domain]').forEach((chip) => {
    chip.addEventListener('click', () => { els.input.value = chip.dataset.domain; runCheck(chip.dataset.domain); });
  });

  els.input.addEventListener('input', () => {
    if (!els.error.hidden) { els.error.hidden = true; lastRender = null; }
  });

  els.copyPem.addEventListener('click', async () => {
    const text = els.certPem.textContent;
    if (!text) return;
    const ok = await copyText(text);
    els.copyPem.textContent = t(ok ? 'certdetails.copied' : 'certdetails.copyFail');
    setTimeout(() => { els.copyPem.textContent = t('certdetails.copy'); }, 1800);
  });

  els.copyChain.addEventListener('click', () => {
    const host = lastRender && lastRender.type === 'result' ? lastRender.data.host : null;
    if (host) copyChain(host);
  });

  els.shareLink.addEventListener('click', () => {
    const host = lastRender && lastRender.type === 'result' ? lastRender.data.host : null;
    copyShareLink(host);
  });

  els.copyResult.addEventListener('click', copyCurrentResult);

  els.copyCurl.addEventListener('click', () => copyCommand('curl'));
  els.copyOpenssl.addEventListener('click', () => copyCommand('openssl'));

  if (els.themeToggle) {
    els.themeToggle.addEventListener('click', () => applyTheme(detectTheme() === 'light' ? 'dark' : 'light'));
  }

  els.addReminder.addEventListener('click', downloadReminder);

  els.downloadPem.addEventListener('click', () => {
    const host = lastRender && lastRender.type === 'result' ? lastRender.data.host : null;
    downloadSinglePem(host);
  });

  els.downloadChain.addEventListener('click', () => {
    const host = lastRender && lastRender.type === 'result' ? lastRender.data.host : null;
    if (host) downloadChain(host);
  });

  els.historyClear.addEventListener('click', () => {
    history = [];
    try { localStorage.removeItem('ssl-ee-history'); } catch { /* privaatrežiim */ }
    renderHistory();
  });

  els.footerYear.textContent = '© ' + new Date().getFullYear() + ' ssl.ee';

  /* ---------- Käivitus ---------- */
  applyTheme(detectTheme());
  applyI18n();

  // Jagatav link: ?d=domeen.ee käivitab kontrolli automaatselt
  try {
    const shared = new URLSearchParams(location.search).get('d');
    if (shared) {
      els.input.value = shared;
      runCheck(shared);
    }
  } catch { /* ignore */ }
})();
