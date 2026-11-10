/* ssl.ee — SSL-sertifikaadi kontrollija
 * Staatiline leht: kõik päringud käivad kasutaja brauseris.
 * Andmeallikad: Cert Spotter (CT logid, primaarne), crt.sh (varu),
 * MDN HTTP Observatory (turvapeadete hinne, valikuline boonus).
 */
(() => {
  'use strict';

  /* ---------- Config ---------- */
  const CONFIG = {
    warnDays: 30,        // alla selle jäänud päevade arv = hoiatus
    sanPreview: 8,       // mitu domeeni enne "näita kõiki"
    historyMax: 8,
    timeouts: { certspotter: 15000, crtsh: 30000, observatory: 20000 },
    observatory: true,   // turvapeadete hinne (MDN HTTP Observatory)
  };

  const CS_API = 'https://api.certspotter.com/v1/issuances';
  const CRTSH_API = 'https://crt.sh/';
  const OBS_API = 'https://observatory-api.mdn.mozilla.net/api/v2/scan';
  const SSLLABS_URL = 'https://www.ssllabs.com/ssltest/analyze.html?d=';

  /* ---------- i18n ---------- */
  const I18N = {
    et: {
      'meta.title': 'ssl.ee — SSL-sertifikaadi kontrollija',
      'hero.badge': 'Tasuta tööriist · andmed Certificate Transparency logidest',
      'hero.title': 'Kas sinu domeeni <span class="grad">SSL-sertifikaat</span> on veel kehtiv?',
      'hero.subtitle': 'Sisesta domeeninimi ja vaata ühe klikiga, kuni sertifikaat kehtib, kes selle välja andis ja milliseid aadresse see kaitseb.',
      'form.placeholder': 'sinudomeen.ee',
      'form.ariaLabel': 'Kontrollitav domeen',
      'form.button': 'Kontrolli',
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
      'sans.title': 'Kaitstud domeenid ({n})',
      'sans.more': 'Näita kõiki ({n})',
      'sans.less': 'Näita vähem',
      'badge.revoked': 'Tühistatud',
      'badge.revokedFull': 'Sertifikaat on väljaandja poolt tühistatud (revoked)',
      'advice.valid': 'Kõik on korras – järgmise uuendamiseni pole vaja midagi ette võtta.',
      'advice.expiring': 'Uuenda sertifikaat varakult, et vältida teenuse katkemist.',
      'advice.expired': 'Uuenda sertifikaat viivitamatult – muidu brauserid ei pruugi saiti enam avada.',
      'source.note': 'Andmed: Certificate Transparency logid ({source}) · kuvatud on uusim väljaanne',
      'obs.title': 'Turvapeadete hinne',
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
      'faq2.a': 'Sertifikaadi andmed loetakse Certificate Transparency logidest teenuse Cert Spotter kaudu (varuallikaks crt.sh) ja turvapeadete hinne tuleb MDN HTTP Observatoryst. Kõik päringud käivad otse sinu brauseris.',
      'faq3.q': 'Miks kuvatud info võib tegelikust erineda?',
      'faq3.a': 'CT logidest kuvatakse uusim välja antud sertifikaat. Server või CDN teenindab mõnikord varasemat või muud sertifikaati – täielikuks analüüsiks (sh protokollid ja šifrid) kasuta allpool olevat SSL Labsi linki.',
      'faq4.q': 'Mis tähendab „aegub varsti“?',
      'faq4.a': 'Sertifikaadile on jäänud alla 30 päeva. Soovitame uuendada kohe – nii ei satu leht uuenduse ununemise tõttu kättesaamatuks.',
      'faq5.q': 'Kas kasutamine on tasuta?',
      'faq5.a': 'Jah. ssl.ee on tasuta, ei nõua registreerimist ega kogu isikuandmeid. Küll võivad kehtida andmeallikate endi päringupiirangud.',
      'footer.tagline': 'Privaatsust austav SSL-sertifikaadi kontrollija – kõik päringud käivad sinu brauseris.',
      'footer.sources': 'Andmeallikad: Cert Spotter · crt.sh · MDN HTTP Observatory',
    },
    en: {
      'meta.title': 'ssl.ee — SSL certificate checker',
      'hero.badge': 'Free tool · data from Certificate Transparency logs',
      'hero.title': 'Is your domain\'s <span class="grad">SSL certificate</span> still valid?',
      'hero.subtitle': 'Enter a domain name and instantly see how long the certificate is valid, who issued it, and which hostnames it protects.',
      'form.placeholder': 'yourdomain.com',
      'form.ariaLabel': 'Domain to check',
      'form.button': 'Check',
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
      'faq2.a': 'Certificate data is read from Certificate Transparency logs via Cert Spotter (with crt.sh as backup); the security-header score comes from MDN HTTP Observatory. All requests run directly in your browser.',
      'faq3.q': 'Why might the information differ from reality?',
      'faq3.a': 'We show the most recently issued certificate from the CT logs. A server or CDN may sometimes serve a different (e.g. older) certificate – for a full analysis (protocols and ciphers included) use the SSL Labs link below.',
      'faq4.q': 'What does "expiring soon" mean?',
      'faq4.a': 'Less than 30 days remain on the certificate. We recommend renewing right away so the site doesn\'t go dark because a renewal was forgotten.',
      'faq5.q': 'Is it free to use?',
      'faq5.a': 'Yes. ssl.ee is free, requires no sign-up and collects no personal data. The upstream data sources may apply their own rate limits.',
      'footer.tagline': 'A privacy-respecting SSL certificate checker – every query runs in your browser.',
      'footer.sources': 'Data sources: Cert Spotter · crt.sh · MDN HTTP Observatory',
    },
  };

  /* ---------- Element refs ---------- */
  const $ = (id) => document.getElementById(id);
  const els = {
    form: $('check-form'), input: $('domain-input'), btn: $('check-btn'),
    scan: $('scan-state'), scanHost: $('scan-host'), scanMsg: $('scan-msg'),
    error: $('error-state'), errorMsg: $('error-msg'), errorLinks: $('error-links'),
    card: $('result-card'),
    statusIcon: $('status-icon'), statusTitle: $('status-title'), statusDomain: $('status-domain'),
    statusChip: $('status-chip'), advice: $('advice'),
    gaugeProgress: $('gauge-progress'), gaugeNumber: $('gauge-number'),
    gaugeLabel: $('gauge-label'), gaugeCaption: $('gauge-caption'),
    detailIssuer: $('detail-issuer'), detailFrom: $('detail-from'),
    detailUntil: $('detail-until'), detailFp: $('detail-fp'),
    sanTitle: $('san-title'), sanList: $('san-list'), sanToggle: $('san-toggle'),
    badges: $('badges'),
    obs: $('obs'), obsGrade: $('obs-grade'), obsScore: $('obs-score'), obsLink: $('obs-link'),
    sourceNote: $('source-note'), linkSsllabs: $('link-ssllabs'), linkCrtsh: $('link-crtsh'),
    history: $('history'), historyList: $('history-list'), historyClear: $('history-clear'),
    footerYear: $('footer-year'),
  };

  /* ---------- State ---------- */
  let lang = detectLang();
  let history = loadHistory();
  let lastRender = null;   // viimane olek keelevalve jaoks uuesti joonistamiseks
  let checkCounter = 0;    // aegunud asünkroonsete vastuste eiramiseks
  let sansExpanded = false;

  function detectLang() {
    try {
      const saved = localStorage.getItem('ssl-ee-lang');
      if (saved === 'et' || saved === 'en') return saved;
    } catch { /* privaatne režiim */ }
    return 'et'; // ssl.ee on eestikeelne sait — vaikimisi eesti keel
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

  /* ---------- i18n rakendamine ---------- */
  function applyI18n() {
    document.documentElement.lang = lang;
    document.title = t('meta.title');
    document.querySelectorAll('[data-i18n]').forEach((el) => { el.textContent = t(el.dataset.i18n); });
    document.querySelectorAll('[data-i18n-html]').forEach((el) => { el.innerHTML = t(el.dataset.i18nHtml); });
    document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => { el.placeholder = t(el.dataset.i18nPlaceholder); });
    document.querySelectorAll('[data-i18n-aria-label]').forEach((el) => { el.setAttribute('aria-label', t(el.dataset.i18nAriaLabel)); });
    const et = $('lang-et'), en = $('lang-en');
    if (et) et.setAttribute('aria-pressed', String(lang === 'et'));
    if (en) en.setAttribute('aria-pressed', String(lang === 'en'));
    renderHistory();
    if (lastRender) rerenderDynamic();
  }

  function setLang(next) {
    if (next === lang) return;
    lang = next;
    try { localStorage.setItem('ssl-ee-lang', lang); } catch { /* privaatne režiim */ }
    applyI18n();
  }

  function rerenderDynamic() {
    if (!lastRender) return;
    if (lastRender.type === 'result') renderResult(lastRender.data);
    else if (lastRender.type === 'error') renderError(lastRender.data);
    else if (lastRender.type === 'scan') showScan(lastRender.host, lastRender.msg);
  }

  /* ---------- Abifunktsioonid ---------- */
  function hideStates() {
    els.scan.hidden = true;
    els.error.hidden = true;
    els.card.hidden = true;
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
      const res = await fetch(url, { method: o.method || 'GET', signal: ctrl.signal, cache: 'no-store' });
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
    };
  }

  async function queryCertspotter(host, subdomains) {
    const params = new URLSearchParams({ domain: host, include_subdomains: subdomains ? 'true' : 'false' });
    params.append('expand', 'dns_names');
    params.append('expand', 'issuer');
    const rows = await fetchJson(CS_API + '?' + params.toString(), { timeout: CONFIG.timeouts.certspotter });
    if (!Array.isArray(rows)) return [];
    return rows.map(normCs).filter((c) => Number.isFinite(c.notBefore) && Number.isFinite(c.notAfter));
  }

  async function queryCrtsh(host) {
    const rows = await fetchJson(CRTSH_API + '?q=' + encodeURIComponent(host) + '&output=json', { timeout: CONFIG.timeouts.crtsh });
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

    renderSans(c.dnsNames, host);

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

    let entries = null;
    let source = null;
    let anySuccess = false;

    // 1) Cert Spotter — täpne vaste
    try {
      const rows = await queryCertspotter(host, false);
      anySuccess = true;
      if (rows.length) { entries = rows; source = 'Cert Spotter'; }
    } catch { /* edasi */ }
    if (stale()) { els.btn.disabled = false; return; }

    // 2) Cert Spotter — koos alamdomeenidega, filtreerime hosti katvad
    if (!entries) {
      try {
        const rows = await queryCertspotter(host, true);
        anySuccess = true;
        const filtered = rows.filter((e) => coversHost(e, host));
        if (filtered.length) { entries = filtered; source = 'Cert Spotter'; }
      } catch { /* edasi */ }
      if (stale()) { els.btn.disabled = false; return; }
    }

    // 3) crt.sh varuallikas
    if (!entries) {
      showScan(host, t('scan.fallback'));
      try {
        const rows = await queryCrtsh(host);
        anySuccess = true;
        if (rows.length) { entries = rows; source = 'crt.sh'; }
      } catch { /* edasi */ }
      if (stale()) { els.btn.disabled = false; return; }
    }

    // Turvapeadete hinne (ei blokeeri põhitulemust)
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
        const data = { host, cert: picked.cert, hasActive: picked.hasActive, source, obs: null };
        renderResult(data);
        addHistory(host, statusOf(picked.cert, picked.hasActive), daysLeftOf(picked.cert));
        obsPromise.then((d) => {
          if (stale()) return;
          data.obs = d;
          if (lastRender && lastRender.type === 'result' && lastRender.data.host === host) fillObservatory(d);
        });
      }
    }
    els.btn.disabled = false;
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

  document.querySelectorAll('.chip[data-domain]').forEach((chip) => {
    chip.addEventListener('click', () => { els.input.value = chip.dataset.domain; runCheck(chip.dataset.domain); });
  });

  els.input.addEventListener('input', () => {
    if (!els.error.hidden) { els.error.hidden = true; lastRender = null; }
  });

  const etBtn = $('lang-et'), enBtn = $('lang-en');
  if (etBtn) etBtn.addEventListener('click', () => setLang('et'));
  if (enBtn) enBtn.addEventListener('click', () => setLang('en'));

  els.historyClear.addEventListener('click', () => {
    history = [];
    try { localStorage.removeItem('ssl-ee-history'); } catch { /* privaatrežiim */ }
    renderHistory();
  });

  els.footerYear.textContent = '© ' + new Date().getFullYear() + ' ssl.ee';

  /* ---------- Käivitus ---------- */
  applyI18n();
})();
