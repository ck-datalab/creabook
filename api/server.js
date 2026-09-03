/**
 * Créa'Book — API Backend (Node.js/Express)
 * Routes : GET /token  POST /upload  POST /submit
 * Env    : HUBSPOT_TOKEN, TOKEN_SECRET
 */

const express  = require('express');
const multer   = require('multer');
const crypto   = require('crypto');
const path     = require('path');
const FormData = require('form-data');
const { Resend } = require('resend');

const app  = express();
const PORT = 8080;

const HUBSPOT_TOKEN  = process.env.HUBSPOT_TOKEN;
const TOKEN_SECRET   = process.env.TOKEN_SECRET;
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const RESEND_FROM          = process.env.RESEND_FROM          || 'Créa\'Book <creabook@cecca.fr>';
const RESEND_JURIDIQUE_CECCA  = process.env.RESEND_JURIDIQUE_CECCA  || '';
const RESEND_JURIDIQUE_ETOILE = process.env.RESEND_JURIDIQUE_ETOILE || '';

if (!HUBSPOT_TOKEN) throw new Error('HUBSPOT_TOKEN manquant');
if (!TOKEN_SECRET)  throw new Error('TOKEN_SECRET manquant');
if (!RESEND_API_KEY) console.warn('[resend] RESEND_API_KEY absent — emails désactivés');

const resendClient = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;

// ── Managers Cecca Étoile (source unique — modifier ici uniquement) ───────────
const ETOILE_MANAGERS = new Set(['SIMBOU DANFAKHA', 'YANN POINLOUP', 'MATEUS SOUTELO', 'JULIEN DECLERCQ']);
const isEtoile = name => ETOILE_MANAGERS.has((name || '').trim().toUpperCase());

// ── Cache HubSpot pipeline + owners ──────────────────────────────────────────

let DEAL_PIPELINE_ID      = null;
let DEAL_STAGE_ID         = null;
let OWNERS_BY_NAME        = {};
let OWNERS_LIST           = [];
let OWNERS_EMAIL_BY_ID    = {};   // ownerId → email (pour rapport Resend)

async function initHubSpotCache() {
  try {
    const pRes  = await fetch('https://api.hubapi.com/crm/v3/pipelines/deals', {
      headers: { Authorization: `Bearer ${HUBSPOT_TOKEN}` },
    });
    const pData = await pRes.json();
    const pipe  = (pData.results || []).find(p => p.label.trim().toLowerCase() === 'juridique mission exceptionnelle');
    if (pipe) {
      DEAL_PIPELINE_ID = pipe.id;
      const stage = (pipe.stages || []).find(s => s.label.trim().toLowerCase() === 'accord verbal')
                 || (pipe.stages || []).sort((a, b) => a.displayOrder - b.displayOrder)[0];
      if (stage) DEAL_STAGE_ID = stage.id;
    }
    console.log(`Pipeline deal : ${DEAL_PIPELINE_ID} / étape : ${DEAL_STAGE_ID}`);
  } catch (e) {
    console.error('initHubSpotCache pipelines :', e.message);
  }

  try {
    let after = null;
    do {
      const url   = `https://api.hubapi.com/crm/v3/owners/?${after ? `after=${after}` : ''}`;
      const oRes  = await fetch(url, { headers: { Authorization: `Bearer ${HUBSPOT_TOKEN}` } });
      const oData = await oRes.json();
      (oData.results || []).forEach(o => {
        const full = `${o.firstName || ''} ${o.lastName || ''}`.trim();
        if (full) {
          OWNERS_BY_NAME[full.toUpperCase()] = o.id;
          if (!OWNERS_LIST.find(x => x.id === o.id)) OWNERS_LIST.push({ name: full, id: o.id });
        }
        if (o.id && o.email) OWNERS_EMAIL_BY_ID[String(o.id)] = o.email;
      });
      after = oData.paging?.next?.after || null;
    } while (after);
    OWNERS_LIST.sort((a, b) => a.name.localeCompare(b.name, 'fr'));
    console.log(`Owners chargés : ${OWNERS_LIST.length}`);
  } catch (e) {
    console.error('initHubSpotCache owners :', e.message);
  }

}

initHubSpotCache();

const ALLOWED_ORIGINS = [
  'https://creabook.cecca.fr',
  'http://localhost:8080',
  'http://localhost',
];

const ALLOWED_TYPES = ['application/pdf', 'image/jpeg', 'image/png', 'image/webp', 'image/gif'];
const MAX_SIZE      = 15 * 1024 * 1024;

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_SIZE } });

// ── HTTPS redirect ────────────────────────────────────────────────────────────

app.use((req, res, next) => {
  if (req.headers['x-forwarded-proto'] === 'http')
    return res.redirect(301, 'https://' + req.headers.host + req.url);
  next();
});

// ── CORS ──────────────────────────────────────────────────────────────────────

app.use((req, res, next) => {
  const origin  = req.headers.origin || '';
  const allowed = ALLOWED_ORIGINS.some(o => origin.startsWith(o));
  if (allowed) res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (!allowed && req.headers.origin) return res.status(403).json({ error: 'Origine non autorisée' });
  next();
});

app.use(express.json());

// ── Draft tokens (30 jours, signés) ──────────────────────────────────────────

function makeDraftToken(data) {
  const payload = Buffer.from(JSON.stringify(data)).toString('base64url');
  const sig     = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('hex');
  return payload + '.' + sig;
}

function parseDraftToken(token) {
  if (!token) return null;
  const dot = token.lastIndexOf('.');
  if (dot < 0) return null;
  const payload  = token.slice(0, dot);
  const sig      = token.slice(dot + 1);
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('hex');
  try { if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'))) return null; }
  catch { return null; }
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (Date.now() > data.expiresAt) return { ...data, expired: true };
    return data;
  } catch { return null; }
}

// ── Tokens HMAC (5 min, signés) ───────────────────────────────────────────────

function makeToken() {
  const id     = crypto.randomUUID();
  const expiry = Date.now() + 5 * 60 * 1000;
  const sig    = crypto.createHmac('sha256', TOKEN_SECRET).update(`${id}:${expiry}`).digest('hex');
  return `${id}:${expiry}:${sig}`;
}

function checkToken(token) {
  if (!token) return false;
  const parts = token.split(':');
  if (parts.length !== 3) return false;
  const [id, expiry, sig] = parts;
  if (Date.now() > parseInt(expiry)) return false;
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(`${id}:${expiry}`).digest('hex');
  try { return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex')); }
  catch { return false; }
}

// ── Routes ────────────────────────────────────────────────────────────────────

app.get('/owners', (_req, res) => {
  res.json({ owners: OWNERS_LIST });
});

app.get('/token', (_req, res) => {
  res.json({ token: makeToken() });
});

// ── GET /company-lookup — lookup PM company by SIREN in HubSpot ──────────────
// SÉCURITÉ : ne retourne que la dénomination + données non personnelles.
// Les champs téléphone, email et coordonnées de contact ne sont jamais exposés.

app.get('/company-lookup', async (req, res) => {
  const siren = (req.query.siren || '').trim();
  if (!/^[0-9]{9}$/.test(siren)) return res.status(400).json({ error: 'SIREN invalide' });

  // Exclure les fiches brouillon (créées par /draft avec siren_pappers fictif)
  const DRAFT_SIRENS = new Set(['000000000']);
  if (DRAFT_SIRENS.has(siren)) return res.json({ found: false });

  const search = await hs('POST', '/crm/v3/objects/companies/search', {
    filterGroups: [{
      filters: [
        { propertyName: 'siren_pappers', operator: 'EQ', value: siren },
      ]
    }],
    properties: [
      'name',
      'forme_juridique_pappers', 'capital_pappers', 'cb_rcs_pappers',
      'adresse_pappers', 'code_postal_pappers', 'ville_pappers',
      'address', 'zip', 'city', 'country',
    ],
    limit: 1,
  });

  if (search.code !== 200 || !(search.data.results || []).length) {
    return res.json({ found: false });
  }

  const company = search.data.results[0];
  const p       = company.properties || {};
  const name    = (p.name || '').replace(/\s*\(En création\)\s*$/i, '').trim();

  // Pappers stores full form name ("EURL, entreprise unipersonnelle…") — extract known abbreviation
  const PM_ABBREVS  = ['SASU','SAS','SARL','EURL','SA','SCI','SNC','SCP','SC'];
  const formeRaw    = p.forme_juridique_pappers || '';
  const upperFirst  = formeRaw.split(',')[0].trim().toUpperCase();
  const formeCode   = PM_ABBREVS.includes(upperFirst) ? upperFirst : '';

  // Pappers formats capital as "1 000 €" — strip to digits only
  const capitalRaw = p.capital_pappers || '';
  const capital    = capitalRaw.replace(/[^0-9]/g, '');

  // Prefer Pappers custom props for address, fall back to standard HubSpot fields
  const adresse = p.adresse_pappers || p.address || '';
  const cp      = p.code_postal_pappers || p.zip || '';
  const ville   = p.ville_pappers || p.city      || '';
  const pays    = p.country                      || '';

  // Fetch contact principal de la société → email + phone
  // L'API v4 expose le label "Primary" qui identifie le contact principal HubSpot
  let pm_email = '';
  let pm_tel   = '';
  try {
    const assocRes = await hs('GET', `/crm/v4/objects/companies/${company.id}/associations/contacts`, null);
    const assocList = (assocRes.code === 200 && assocRes.data.results) || [];
    if (assocList.length) {
      // Préférer le contact avec label "Primary", sinon prendre le premier de la liste
      const primary = assocList.find(r =>
        (r.associationTypes || []).some(t => t.label === 'Primary')
      ) || assocList[0];
      const contactId = primary.toObjectId;
      if (contactId) {
        const ctRes = await hs('GET', `/crm/v3/objects/contacts/${contactId}?properties=email,mobilephone,phone`, null);
        if (ctRes.code === 200) {
          const ctp = ctRes.data.properties || {};
          pm_email = ctp.email       || '';
          pm_tel   = ctp.mobilephone || ctp.phone || '';
        }
      }
    }
  } catch (_) { /* non-bloquant — on continue sans les coordonnées */ }

  res.json({
    found: true,
    data: {
      pm_denom:   name,
      pm_forme:   formeCode,
      pm_capital: capital,
      pm_rcs:     p.cb_rcs_pappers || '',
      pm_adresse: adresse,
      pm_cp:      cp,
      pm_ville:   ville,
      pm_pays:    pays,
      pm_email,
      pm_tel,
    },
  });
});

// ── POST /draft — collab saves partial state ──────────────────────────────────

app.post('/draft', async (req, res) => {
  const body = req.body;
  if (!checkToken(body.token || '')) return res.status(403).json({ error: 'Token invalide' });

  const state  = body.state || {};
  const hsF    = state.hsFields || {};

  // cb_manager détermine l'entité (Étoile ou CECCA) ; owner est le propriétaire du deal
  const draftManagerName = s(hsF.cb_manager || (state.owner && state.owner.name));
  const draftEtoile      = isEtoile(draftManagerName);

  // siren_pappers : '000000000' = marqueur brouillon, exclu par /company-lookup
  const companyProps = { name: (s(hsF.cb_denomination_sociale) || 'Brouillon') + ' (En création)', siren_pappers: '000000000' };
  if (s(hsF.cb_forme_juridique))       companyProps.forme_juridique_pappers = s(hsF.cb_forme_juridique);
  if (s(hsF.cb_capital_social))        companyProps.capital_pappers         = s(hsF.cb_capital_social);
  if (s(hsF.cb_objet_social))          companyProps.objet_social_pappers    = s(hsF.cb_objet_social);
  if (s(hsF.cb_siege_adresse))         companyProps.address                 = s(hsF.cb_siege_adresse);
  if (s(hsF.cb_siege_cp))              companyProps.zip                     = s(hsF.cb_siege_cp);
  if (s(hsF.cb_siege_ville))           companyProps.city                    = s(hsF.cb_siege_ville);
  if (s(hsF.cb_date_debut))            companyProps.cb_date_debut_activite  = s(hsF.cb_date_debut);
  if (s(hsF.cb_type_parcours))         companyProps.cb_type_parcours        = s(hsF.cb_type_parcours);
  if (s(hsF.cb_montant_nominal_part))  companyProps.cb_montant_nominal_part = s(hsF.cb_montant_nominal_part);
  if (s(hsF.cb_banque_nom))            companyProps.cb_banque_nom           = s(hsF.cb_banque_nom);
  if (s(hsF.cb_banque_adresse))        companyProps.cb_banque_adresse       = s(hsF.cb_banque_adresse);
  if (draftManagerName)                companyProps.manager                 = draftManagerName;
  companyProps.entite         = draftEtoile ? 'CECCA Étoile' : 'CECCA';
  companyProps.cb_source      = 'Créabook';
  companyProps.lifecyclestage = 'lead';

  const compRes   = await hs('POST', '/crm/v3/objects/companies', { properties: companyProps });
  const companyId = compRes.code < 300 ? (compRes.data.id || null) : null;

  const draftData = {
    companyId,
    state:          body.state || {},
    filledByCollab: body.filledByCollab || {},
    expiresAt:      Date.now() + 30 * 24 * 60 * 60 * 1000,
  };
  const token = makeDraftToken(draftData);
  const url   = `https://creabook.cecca.fr/?draft=${encodeURIComponent(token)}`;

  res.json({ ok: true, url, companyId });
});

// ── GET /draft/:token — client loads pre-filled state ────────────────────────

app.get('/draft/:token', (req, res) => {
  const data = parseDraftToken(decodeURIComponent(req.params.token));
  if (!data)         return res.status(400).json({ error: 'Lien invalide ou corrompu' });
  if (data.expired)  return res.status(410).json({ error: 'Lien expiré (30 jours)', expired: true });
  res.json({ ok: true, state: data.state, filledByCollab: data.filledByCollab, companyId: data.companyId });
});

app.post('/upload', upload.single('file'), async (req, res) => {
  if (!checkToken(req.body.token))
    return res.status(403).json({ error: 'Token invalide ou expiré' });

  const file = req.file;
  if (!file) return res.status(400).json({ error: 'Fichier manquant' });
  if (!ALLOWED_TYPES.includes(file.mimetype))
    return res.status(415).json({ error: 'Type non autorisé : ' + file.mimetype });

  let folder = (req.body.folder || '/creabook/dossiers').replace(/[^a-zA-Z0-9_\-\/]/g, '_');
  if (!folder.startsWith('/creabook/')) folder = '/creabook/dossiers';

  const hsForm = new FormData();
  hsForm.append('file', file.buffer, { filename: file.originalname, contentType: file.mimetype });
  hsForm.append('options', JSON.stringify({ access: 'PRIVATE', overwrite: true }), { contentType: 'application/json', filename: 'options.json' });
  hsForm.append('folderPath', folder);

  try {
    const hsRes  = await fetch('https://api.hubapi.com/files/v3/files', {
      method: 'POST',
      headers: { Authorization: `Bearer ${HUBSPOT_TOKEN}`, ...hsForm.getHeaders() },
      body: hsForm.getBuffer(),
    });
    const hsData = await hsRes.json();
    if (hsRes.ok) return res.json({ ok: true, url: hsData.url, id: hsData.id, name: hsData.name });
    return res.status(502).json({ error: 'Échec upload HubSpot', code: hsRes.status, detail: hsData });
  } catch (e) {
    return res.status(502).json({ error: 'Erreur réseau', detail: e.message });
  }
});

app.post('/submit', async (req, res) => {
  try {
  const body = req.body;
  if (!checkToken(body.token || ''))
    return res.status(403).json({ error: 'Token invalide ou expiré' });

  const errors       = [];
  const contactEntries = [];

  console.log('[submit] entity:', body.entity, '| manager:', body.manager);
  console.log('[submit] societe.nom:', (body.societe || {}).nom, '| forme:', (body.societe || {}).forme);
  console.log('[submit] mandatairesAssoc:', (body.mandatairesAssoc || []).length, '| mandatairesNonAssoc:', (body.mandatairesNonAssoc || []).length, '| associesNonMdt:', (body.associesNonMdt || []).length);
  console.log('[submit] draftCompanyId:', body.draftCompanyId || null);

  async function processPerson(d, label) {
    if ((d.pm_type || 'pp') === 'pm') {
      const cid   = await createContactPM(d);
      const pmCid = await createCompanyPM(d);
      if (cid)   contactEntries.push({ id: cid,   label: label + ' (RL)', fileIds: d.fileIds || [], note: `Pièces jointes Créa'Book — ${label}` });
      if (pmCid) contactEntries.push({ pmCompanyId: pmCid, rlContactId: cid, label: label + ' (PM)' });
    } else {
      const cid = await createContactPP(d);
      if (cid) contactEntries.push({ id: cid, label, fileIds: d.fileIds || [], note: `Pièces jointes Créa'Book — ${label}` });
      else errors.push(`Échec création contact ${label}`);
    }
  }

  for (let i = 0; i < (body.mandatairesAssoc || []).length; i++)
    await processPerson(body.mandatairesAssoc[i], `Mandataire associé ${i + 1}`);
  for (let j = 0; j < (body.mandatairesNonAssoc || []).length; j++)
    await processPerson(body.mandatairesNonAssoc[j], `Mandataire non associé ${j + 1}`);
  for (let k = 0; k < (body.associesNonMdt || []).length; k++)
    await processPerson(body.associesNonMdt[k], `Associé non mandataire ${k + 1}`);

  console.log('[submit] contacts créés:', contactEntries.length, '| erreurs:', errors);

  const soc         = body.societe || {};
  const managerName = s(body.manager);
  // Priorité : ownerId envoyé directement par le frontend (= _selectedOwner.id, choix étape 1)
  // Fallback  : résolution par nom via OWNERS_BY_NAME (ancien comportement)
  const ownerId     = s(body.ownerId) || (managerName ? (OWNERS_BY_NAME[managerName.toUpperCase()] || null) : null);
  const entiteLabel = body.entity === 'cecca_etoile' ? 'Cecca Étoile' : 'Cecca';
  const entiteEnum  = body.entity === 'cecca_etoile' ? 'CECCA Étoile' : 'CECCA';

  console.log('[submit] ownerId pour', managerName, ':', ownerId, '| direct:', s(body.ownerId));

  // ════════════════════════════════════════════════════════════════════════════
  //  MAPPING : champ Créabook  →  propriété HubSpot
  //  Pour corriger un nom de propriété HubSpot, modifiez uniquement la valeur
  //  à droite du « : ». La clé à gauche est le nom du champ Créabook.
  // ════════════════════════════════════════════════════════════════════════════

  // ── Société (objet "companies") ───────────────────────────────────────────
  const companyMapping = {
    // Identité
    nom:             'name',               // denomination_sociale → name HubSpot
    forme:           'forme_juridique_pappers',
    capital:         'capital_pappers',
    objet:           'objet_social_pappers',
    // Siège social
    siege_adresse:   'adresse_pappers',            // ← si non visible dans HubSpot, corriger ici
    siege_cp:        'code_postal_pappers',
    siege_ville:     'ville_pappers',
    // Infos Créa'Book
    date_debut:      'cb_date_debut_activite',
    type_parcours:   'cb_type_parcours',
    montant_nominal: 'cb_montant_nominal_part',
    banque_nom:      'cb_banque_nom',
    banque_adresse:  'cb_banque_adresse',
    activite:        'pole_sectoriel',
  };

  const companyProps = {
    // Valeur fixe « En création »
    [companyMapping.nom]: (s(soc.nom) || 'Société') + ' (En création)',
    siren_pappers:        '999999999',
    // Cycle de vie + source
    lifecyclestage:       'customer',      // valeur interne HubSpot ('Client' est le label affiché)
    cb_source:            'Créabook',
    // Manager / entité
    entite:               entiteEnum,
  };

  // Champs optionnels issus du mapping
  for (const [crField, hsField] of Object.entries(companyMapping)) {
    if (crField === 'nom') continue; // déjà traité ci-dessus
    const v = s(soc[crField]);
    if (v) companyProps[hsField] = v;
  }

  if (managerName) companyProps.manager = managerName;

  // ── CNI des associés → fiche entreprise ─────────────────────────────────
  const allPersons = [
    ...(body.mandatairesAssoc    || []),
    ...(body.mandatairesNonAssoc || []),
    ...(body.associesNonMdt      || []),
  ];
  const cniUrls = allPersons
    .map(d => ((d.pm_type || 'pp') === 'pm' ? (d.fileDocs || {}).pm_cni_rl : (d.fileDocs || {}).cni))
    .filter(Boolean);
  if (cniUrls.length) companyProps.cartes_didentite_des_associes = cniUrls.join('\n');

  const diplomeUrls = allPersons
    .map(d => (d.fileDocs || {}).diplome)
    .filter(Boolean);
  if (diplomeUrls.length) companyProps.diplomes_des_associes = diplomeUrls.join('\n');

  const cniPmUrls = allPersons
    .filter(d => (d.pm_type || 'pp') === 'pm')
    .flatMap(d => [(d.fileDocs || {}).pm_cni_rl, (d.fileDocs || {}).pm_cni_rp].filter(Boolean));
  if (cniPmUrls.length) companyProps.cni_representants_pm = cniPmUrls.join('\n');

  const domicilePmUrls = allPersons
    .filter(d => (d.pm_type || 'pp') === 'pm')
    .map(d => (d.fileDocs || {}).pm_domicile_rp)
    .filter(Boolean);
  if (domicilePmUrls.length) companyProps.domicile_du_representant_permanent = domicilePmUrls.join('\n');

  // ── Transaction (objet "deals") ───────────────────────────────────────────
  const dealMapping = {
    // Société
    objet:           'cb_objet_social',
    siege_adresse:   'cb_siege_adresse',
    siege_cp:        'cb_siege_cp',
    siege_ville:     'cb_siege_ville',
    banque_nom:      'cb_banque_nom',
    banque_adresse:  'cb_banque_adresse',
    type_parcours:   'cb_type_parcours',
    montant_nominal: 'cb_montant_nominal_part',
    date_debut:      'cb_date_debut_activite',
    nb_associes:     'cb_nb_associes',
  };

  const dealProps = {
    // Identité
    dealname:           (s(soc.nom) || 'Nouvelle société') + ' — Création de société',
    montant_de_la_creation: body.entity === 'cecca_etoile' ? '2160' : '900',
    // Pipeline (IDs chargés au démarrage)
    pipeline:           DEAL_PIPELINE_ID || 'default',
    dealstage:          DEAL_STAGE_ID    || 'appointmentscheduled',
    // Manager / entité / source
    cb_source:          'Créabook',
    source:             'Créabook',
    transaction_irpp:   'false',
    creation_a_faire:   'true',
  };

  if (ownerId)    dealProps.hubspot_owner_id = ownerId;

  for (const [crField, hsField] of Object.entries(dealMapping)) {
    const v = s(soc[crField]);
    if (v) dealProps[hsField] = v;
  }

  // ── Création / mise à jour de la société ─────────────────────────────────
  let companyId;
  if (body.draftCompanyId) {
    const patchRes = await hs('PATCH', `/crm/v3/objects/companies/${body.draftCompanyId}`, { properties: companyProps });
    console.log('[submit] PATCH company', body.draftCompanyId, '→', patchRes.code, JSON.stringify(patchRes.data).slice(0, 200));
    companyId = patchRes.code < 300 ? body.draftCompanyId : null;
    if (!companyId) errors.push('Échec mise à jour société brouillon : ' + JSON.stringify(patchRes.data));
  } else {
    const compRes = await hs('POST', '/crm/v3/objects/companies', { properties: companyProps });
    console.log('[submit] POST company →', compRes.code, JSON.stringify(compRes.data).slice(0, 200));
    companyId = compRes.code < 300 ? (compRes.data.id || null) : null;
    if (!companyId) errors.push('Échec création société : ' + JSON.stringify(compRes.data));
  }
  console.log('[submit] companyId:', companyId);

  if (companyId) {
    const socFiles = (soc.fileIds || []).filter(Boolean);
    if (socFiles.length) await createNoteOnCompany(companyId, `Pièces jointes Créa'Book — Documents société`, socFiles);
  }

  for (const entry of contactEntries) {
    if (entry.pmCompanyId && companyId) {
      await associateCompanies(entry.pmCompanyId, companyId);
      if (entry.rlContactId) await associateToCompany(entry.rlContactId, entry.pmCompanyId);
    }
    if (entry.id && companyId) await associateToCompany(entry.id, companyId);
    if (entry.id && entry.note) await createNoteWithFiles(entry.id, entry.note, entry.fileIds || []);
  }

  const ids = contactEntries.filter(e => e.id).map(e => e.id);

  // ── Création de la transaction ────────────────────────────────────────────
  const dealRes = await hs('POST', '/crm/v3/objects/deals', { properties: dealProps });
  console.log('[submit] POST deal →', dealRes.code, JSON.stringify(dealRes.data).slice(0, 200));
  const dealId  = dealRes.code < 300 ? (dealRes.data.id || null) : null;
  if (!dealId) errors.push('Échec création transaction : ' + JSON.stringify(dealRes.data));

  if (dealId && companyId)
    await hs('PUT', `/crm/v4/objects/deals/${dealId}/associations/default/companies/${companyId}`, null);
  for (const cId of ids)
    if (dealId) await hs('PUT', `/crm/v4/objects/deals/${dealId}/associations/default/contacts/${cId}`, null);

  // ── Note consolidée sur le deal avec TOUS les documents ─────────────────────
  if (dealId) {
    const allFileIds = [
      ...(soc.fileIds || []),
      ...contactEntries.flatMap(e => e.fileIds || []),
    ].filter(Boolean);
    const hebergInfo = s(soc.est_heberge) === 'oui'
      ? `\nHébergement : ${s(soc.hebergeur_type) || '—'} | ${[s(soc.hebergeur_nom), s(soc.hebergeur_prenom), s(soc.hebergeur_societe)].filter(Boolean).join(' ')} | SIREN : ${s(soc.hebergeur_siren) || '—'}`
      : '\nHébergement : siège propre';
    const noteLines = [
      `Dossier Créa'Book — ${s(soc.nom) || 'Nouvelle société'}`,
      `Forme : ${s(soc.forme) || '—'} | Capital : ${s(soc.capital) || '—'} € | Parts : ${s(soc.montant_nominal) || '—'} €/part`,
      `Siège : ${[s(soc.siege_adresse), s(soc.siege_cp), s(soc.siege_ville)].filter(Boolean).join(', ') || '—'}`,
      `Objet : ${s(soc.objet) || '—'}`,
      `Date début : ${s(soc.date_debut) || '—'} | Parcours : ${s(soc.type_parcours) || '—'}`,
      `Banque : ${s(soc.banque_nom) || '—'} — ${s(soc.banque_adresse) || '—'}`,
      hebergInfo,
      `Manager : ${managerName || '—'} | Entité : ${entiteLabel}`,
      allFileIds.length ? `\n${allFileIds.length} document(s) joint(s)` : '',
    ].filter(Boolean).join('\n');
    await createNoteOnDeal(dealId, noteLines, allFileIds);
  }

  console.log('[submit] terminé — companyId:', companyId, '| dealId:', dealId, '| contacts:', ids.length, '| erreurs:', errors.length);
  res.json({ ok: errors.length === 0, companyId, contactIds: ids, dealId, errors });

  // Envoi du rapport par email (non-bloquant — après la réponse HTTP)
  sendRapport(body, dealId);

  } catch(e) {
    console.error('[submit] exception non gérée :', e);
    res.status(500).json({ ok: false, error: e.message, errors: [e.message] });
  }
});

// ── Rapport email (Resend) ────────────────────────────────────────────────────

function esc(v) {
  return String(v || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function fmtDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleDateString('fr-FR', { day:'2-digit', month:'long', year:'numeric' });
}

/* ── Styles inline réutilisés ── */
const S = {
  wrap:    'font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#0A0A0A;background:#CFCBC4;padding:32px 16px;',
  shell:   'max-width:680px;margin:0 auto;background:#FAFAF7;',
  hdr:     'background-color:#5B1421;background:linear-gradient(135deg,#5B1421 0%,#3D1B3F 35%,#1A2E4F 70%,#0F1F38 100%);padding:28px 32px 22px;',
  hdrLogo: 'font-family:Arial,sans-serif;font-size:20px;font-weight:800;color:#fff;letter-spacing:.03em;margin-bottom:2px;',
  hdrSub:  'font-size:10px;color:rgba(255,255,255,.5);text-transform:uppercase;letter-spacing:.14em;margin-bottom:18px;',
  hdrLbl:  'font-size:10px;color:rgba(255,255,255,.5);text-transform:uppercase;letter-spacing:.09em;',
  hdrVal:  'font-size:12.5px;color:#fff;font-weight:600;',
  chip:    'display:inline-block;background:#7A1F30;color:#fff;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;padding:4px 12px;border-radius:2px;margin-top:14px;',
  body:    'padding:0 32px 32px;',
  secWrap: 'margin-top:26px;',
  secTtl:  'display:table;margin-bottom:10px;',
  secSq:   'display:table-cell;width:8px;height:14px;background:#7A1F30;border-radius:1px;vertical-align:middle;',
  secLbl:  'display:table-cell;vertical-align:middle;padding-left:8px;font-family:Arial,sans-serif;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.12em;color:#0A0A0A;',
  tbl:     'width:100%;border:1px solid #E8E3DD;border-radius:4px;border-collapse:collapse;',
  tdLbl:   'padding:7px 13px;font-size:12px;color:#6A645B;font-weight:500;width:38%;border-bottom:1px solid #E8E3DD;background:#F5F2EE;vertical-align:top;',
  tdVal:   'padding:7px 13px;font-size:12px;color:#0A0A0A;font-weight:500;border-bottom:1px solid #E8E3DD;vertical-align:top;',
  tdLblW:  'padding:7px 13px;font-size:12px;color:#6A645B;font-weight:500;width:38%;border-bottom:1px solid #E8E3DD;vertical-align:top;',
  tdValW:  'padding:7px 13px;font-size:12px;color:#0A0A0A;font-weight:500;border-bottom:1px solid #E8E3DD;vertical-align:top;',
  pCard:   'border:1px solid #E8E3DD;border-radius:4px;overflow:hidden;margin-bottom:14px;',
  pHdr:    'background-color:#5B1421;background:linear-gradient(135deg,#5B1421 0%,#3D1B3F 35%,#1A2E4F 70%,#0F1F38 100%);padding:11px 16px;',
  pRole:   'font-size:9px;color:rgba(255,255,255,.55);text-transform:uppercase;letter-spacing:.12em;margin-bottom:3px;',
  pName:   'font-size:15px;font-weight:700;color:#fff;',
  pNamePM: 'font-size:15px;font-weight:700;color:#F5C2C8;',
  pSub:    'font-size:9.5px;font-weight:700;color:#7A1F30;text-transform:uppercase;letter-spacing:.1em;padding:8px 13px 5px;background:#FAFAF7;border-bottom:1px solid #E8E3DD;',
  tagOui:  'display:inline-block;background:#E8F2EC;color:#1A6A4F;font-size:10px;font-weight:700;padding:2px 8px;border-radius:2px;text-transform:uppercase;',
  tagNon:  'display:inline-block;background:#FAF0F2;color:#7A1F30;font-size:10px;font-weight:700;padding:2px 8px;border-radius:2px;text-transform:uppercase;',
  tagMor:  'display:inline-block;background:#EEF1F6;color:#1A2E4F;font-size:10px;font-weight:700;padding:2px 8px;border-radius:2px;text-transform:uppercase;',
  tagPhy:  'display:inline-block;background:#F5F2EE;color:#4A4540;font-size:10px;font-weight:700;padding:2px 8px;border-radius:2px;text-transform:uppercase;',
  docChip: 'display:inline-block;background:#EEF1F6;color:#1A2E4F;border:1px solid #C8D4E6;font-size:10.5px;font-weight:500;padding:3px 9px;border-radius:2px;margin:2px 4px 2px 0;',
  montBar: 'background-color:#5B1421;background:linear-gradient(135deg,#5B1421 0%,#3D1B3F 35%,#1A2E4F 70%,#0F1F38 100%);padding:20px 32px;',
  foot:    'background:#F5F2EE;border-top:2px solid #E8E3DD;padding:13px 32px;text-align:center;font-size:10.5px;color:#6A645B;',
};

// Échappe les valeurs texte ; laisse passer le HTML pré-construit (commence par '<')
function safeVal(v) {
  if (v === undefined || v === null || v === '') return '';
  const s = String(v);
  return /^<[a-zA-Z]/.test(s.trimStart()) ? s : esc(s);
}

function row(label, value, even) {
  const bg = even ? '#F5F2EE' : '#FAFAF7';
  return `<tr>
    <td style="${S.tdLbl}background:${bg}">${esc(label)}</td>
    <td style="${S.tdVal}">${value || '<span style="color:#9A938A;font-style:italic">—</span>'}</td>
  </tr>`;
}

function infoTable(rows) {
  const html = rows.map((r, i) => row(r[0], r[1] !== undefined ? safeVal(r[1]) : '', i % 2 === 1)).join('');
  return `<table style="${S.tbl}" cellpadding="0" cellspacing="0">${html}</table>`;
}

function sectionTitle(label) {
  return `<div style="${S.secWrap}">
    <div style="${S.secTtl}">
      <div style="${S.secSq}"></div>
      <span style="${S.secLbl}">${esc(label)}</span>
    </div>`;
}

function tagBool(val) {
  return val === 'oui' ? `<span style="${S.tagOui}">Oui</span>` : `<span style="${S.tagNon}">Non</span>`;
}

function personCard(roleLabel, name, isPM, subsections) {
  const nameStyle = isPM ? S.pNamePM : S.pName;
  return `<div style="${S.pCard}">
    <div style="${S.pHdr}">
      <div style="${S.pRole}">${esc(roleLabel)}</div>
      <div style="${nameStyle}">${esc(name)}</div>
    </div>
    ${subsections}
  </div>`;
}

function sub(label, tableHtml) {
  return `<div style="${S.pSub}">${esc(label)}</div>${tableHtml}`;
}

function subTable(rows) {
  const html = rows.map((r, i) => row(r[0], r[1] !== undefined ? safeVal(r[1]) : '', i % 2 === 1)).join('');
  return `<table style="width:100%;border-collapse:collapse;" cellpadding="0" cellspacing="0">${html}</table>`;
}

function docChips(docs) {
  if (!docs || !docs.length) return '<span style="color:#9A938A;font-style:italic;font-size:12px;padding:10px 13px;display:block;">Aucun document</span>';
  return '<div style="padding:10px 13px;">' + docs.map(d => `<span style="${S.docChip}">${esc(d)}</span>`).join('') + '</div>';
}

const DOC_LABELS = {
  cni:                       'CNI / Passeport',
  domicile:                  'Justificatif de domicile',
  vitale:                    'Carte vitale',
  livret:                    'Livret de famille',
  diplome:                   'Diplôme',
  attestation_hbg:           'Attestation hébergement',
  cni_hbg:                   'CNI hébergeur',
  domicile_hbg:              'Justif. domicile hébergeur',
  attestation_domiciliation: 'Attestation domiciliation',
  pm_cni_rl:                 'CNI représentant légal',
  pm_cni_rp:                 'CNI représentant permanent',
  pm_domicile_rp:            'Justif. domicile représentant permanent',
  pm_kbis:                   'Kbis',
  pm_rbe:                    'RBE',
  domicile_societe:          'Domicile société',
  bail:                      'Contrat de bail',
};

function buildFileLinksSection(body) {
  const soc     = body.societe || {};
  const persons = [
    ...(body.mandatairesAssoc    || []).map((p, i) => ({ p, label: `Mandataire associé ${i + 1} — ${((p.pm_type === 'pm' ? p.pm_denom : (p.prenom || '') + ' ' + (p.nom || '')) || '').trim()}` })),
    ...(body.mandatairesNonAssoc || []).map((p, i) => ({ p, label: `Mandataire non associé ${i + 1} — ${((p.pm_type === 'pm' ? p.pm_denom : (p.prenom || '') + ' ' + (p.nom || '')) || '').trim()}` })),
    ...(body.associesNonMdt      || []).map((p, i) => ({ p, label: `Associé ${i + 1} — ${((p.pm_type === 'pm' ? p.pm_denom : (p.prenom || '') + ' ' + (p.nom || '')) || '').trim()}` })),
  ];

  const linkStyle = 'color:#7A1F30;text-decoration:none;font-weight:600;';
  const chipStyle = 'display:inline-block;background:#FAF0F2;color:#7A1F30;border:1px solid #E8C8CE;font-size:11px;padding:3px 10px;border-radius:2px;margin:2px 4px 2px 0;text-decoration:none;font-weight:600;';

  let sections = '';

  // Pièces par personne
  for (const { p, label } of persons) {
    const docs = p.fileDocs || {};
    const links = Object.entries(docs)
      .filter(([, url]) => url && url.startsWith('http'))
      .map(([key, url]) => `<a href="${url}" style="${chipStyle}">${esc(DOC_LABELS[key] || key)}</a>`);
    if (!links.length) continue;
    sections += `
      <div style="margin-bottom:12px;">
        <div style="font-size:11px;font-weight:700;color:#1A2E4F;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px;">${esc(label)}</div>
        <div>${links.join('')}</div>
      </div>`;
  }

  // Pièces société
  const socDocs = soc.fileDocs || {};
  const socLinks = Object.entries(socDocs)
    .filter(([, url]) => url && url.startsWith('http'))
    .map(([key, url]) => `<a href="${url}" style="${chipStyle}">${esc(DOC_LABELS[key] || key)}</a>`);
  if (socLinks.length) {
    sections += `
      <div style="margin-bottom:12px;">
        <div style="font-size:11px;font-weight:700;color:#1A2E4F;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px;">Documents société</div>
        <div>${socLinks.join('')}</div>
      </div>`;
  }

  if (!sections) return '';

  return `
    ${sectionTitle('Pièces jointes — Liens HubSpot')}
      <div style="padding:12px 14px;background:#F5F2EE;border:1px solid #E8E3DD;border-radius:4px;">
        ${sections}
      </div>
    </div>`;
}

function buildPersonSection(p, roleLabel, showParts) {
  if (!p) return '';
  const isPM = p.pm_type === 'pm';

  if (isPM) {
    const name = p.pm_denom || 'Société';
    const partsRows = showParts ? [
      ['Nombre de parts', p.pm_nb_parts],
      ['Apport numéraire', p.pm_apport_num ? p.pm_apport_num + ' €' : '—'],
      ['Apport en nature', p.pm_apport_nat ? p.pm_apport_nat + ' €' : '—'],
    ] : [];
    const subs = [
      sub('Identification', subTable([
        ['SIREN', p.pm_siren], ['Forme', p.pm_forme], ['Capital', p.pm_capital ? p.pm_capital + ' €' : ''],
        ['RCS', p.pm_rcs], ['Siège social', [p.pm_adresse, p.pm_cp, p.pm_ville].filter(Boolean).join(', ')],
        ['Email', p.pm_email], ['Téléphone', p.pm_tel],
      ])),
      sub('Représentant légal', subTable([
        ['Nom', (p.pm_rl_nom || '') + ' ' + (p.pm_rl_prenom || '')],
        ['Qualité', p.pm_rl_qualite], ['Email', p.pm_rl_email], ['Téléphone', p.pm_rl_tel],
      ])),
      ...(partsRows.length ? [sub('Participation', subTable(partsRows))] : []),
    ].join('');
    return personCard(roleLabel + ' · Personne morale', name, true, subs);
  }

  const name = ((p.prenom || '') + ' ' + (p.nom || '')).trim() || 'Personne physique';
  const hbgType = p.hbg_type || 'physique';
  const hbgRows = p.heberge === 'oui'
    ? hbgType === 'morale'
      ? [['Hébergé ?', tagBool('oui')], ['Type', `<span style="${S.tagMor}">Personne morale</span>`], ['Raison sociale', p.hbg_societe], ['SIREN', p.hbg_siren]]
      : [['Hébergé ?', tagBool('oui')], ['Type', `<span style="${S.tagPhy}">Personne physique</span>`], ['Nom', (p.hbg_nom || '') + ' ' + (p.hbg_prenom || '')]]
    : [['Hébergé ?', tagBool('non')]];

  const partsRows = showParts ? [
    ['Nombre de parts', p.nb_parts],
    ['Apport numéraire', p.apport_num ? p.apport_num + ' €' : '—'],
    ['Apport en nature', p.apport_nat ? p.apport_nat + ' €' : '—'],
    ['ACRE', p.acre ? `<span style="${S.tagOui}">Oui</span>` : `<span style="${S.tagNon}">Non</span>`],
  ] : [];

  const docsMap = p.fileDocs || {};
  const docNames = {
    cni:'CNI / Passeport', domicile:'Justificatif de domicile', vitale:'Carte vitale',
    livret:'Livret de famille', diplome:'Diplôme', cni_hbg:'CNI hébergeur',
    domicile_hbg:'Justif. domicile hébergeur', attestation_hbg:'Attestation hébergement',
    attestation_domiciliation:'Attestation domiciliation',
  };
  const docList = Object.entries(docNames).filter(([k]) => docsMap[k]).map(([,v]) => v);

  const subs = [
    sub('Identité', subTable([
      ['Date de naissance', p.ddn], ['Nationalité', p.nationalite],
      ['N° sécurité sociale', p.num_secu], ['Régime matrimonial', p.regime],
      ['Profession', p.profession],
    ])),
    sub('Coordonnées', subTable([
      ['Adresse', [p.adresse, p.cp, p.ville].filter(Boolean).join(', ')],
      ['Email', p.email], ['Téléphone', p.phone],
    ])),
    ...(partsRows.length ? [sub('Participation', subTable(partsRows))] : []),
    sub('Hébergement', subTable(hbgRows)),
    sub('Documents fournis', docChips(docList)),
  ].join('');

  const roleDisplay = p.role ? `${roleLabel} · ${p.role}` : roleLabel;
  return personCard(roleDisplay, name, false, subs);
}

function buildRapportHTML(body, dateStr, isInternal = false) {
  const soc     = body.societe || {};
  const entity  = body.entity  || 'cecca';
  const entite  = entity === 'cecca_etoile' ? 'Cecca Étoile' : 'Cecca';
  const montant = (soc.type_parcours || '') === 'sci_scpi' ? '2 160 €' : '900 €';
  const iban    = entity === 'cecca_etoile' ? 'FR03 3000 2062 3500 0007 4330 P33' : 'FR76 3000 2062 3500 0007 3467 Z97';
  const benef   = entity === 'cecca_etoile' ? 'CECCA ÉTOILE' : 'CECCA';

  const mdtAssoc    = body.mandatairesAssoc    || [];
  const mdtNonAssoc = body.mandatairesNonAssoc || [];
  const assocNonMdt = body.associesNonMdt      || [];

  const nomSociete = esc(soc.nom || 'Nouvelle société');
  const siege      = [soc.siege_adresse, soc.siege_cp, soc.siege_ville].filter(Boolean).join(', ');

  // Hébergement société
  const hbgOui = soc.est_heberge === 'oui';
  const hbgRows = hbgOui
    ? soc.hebergeur_type === 'morale'
      ? [
          ['Hébergée ?', tagBool('oui')],
          ['Type d\'hébergeur', `<span style="${S.tagMor}">Personne morale</span>`],
          ['Raison sociale', soc.hebergeur_societe],
          ['SIREN hébergeur', soc.hebergeur_siren],
        ]
      : [
          ['Hébergée ?', tagBool('oui')],
          ['Type d\'hébergeur', `<span style="${S.tagPhy}">Personne physique</span>`],
          ['Hébergeur', (soc.hebergeur_prenom || '') + ' ' + (soc.hebergeur_nom || '')],
        ]
    : [['Hébergée ?', tagBool('non')]];

  // Docs société
  const socDocNames = { domicile_societe:'Domicile société', bail:'Contrat de bail' };
  const socFileDocs = (soc.fileDocs || {});
  const socDocList  = Object.entries(socDocNames).filter(([k]) => socFileDocs[k]).map(([,v]) => v);

  const personsHtml = [
    ...(mdtAssoc.length
      ? [`${sectionTitle(`Mandataires associés — ${mdtAssoc.length} personne${mdtAssoc.length > 1 ? 's' : ''}`)}
          ${mdtAssoc.map(p => buildPersonSection(p, 'Mandataire associé', true)).join('')}
         </div>`]
      : []),
    ...(mdtNonAssoc.length
      ? [`${sectionTitle(`Mandataires non associés — ${mdtNonAssoc.length} personne${mdtNonAssoc.length > 1 ? 's' : ''}`)}
          ${mdtNonAssoc.map(p => buildPersonSection(p, 'Mandataire non associé', false)).join('')}
         </div>`]
      : []),
    ...(assocNonMdt.length
      ? [`${sectionTitle(`Associés non mandataires — ${assocNonMdt.length} personne${assocNonMdt.length > 1 ? 's' : ''}`)}
          ${assocNonMdt.map(p => buildPersonSection(p, 'Associé non mandataire', true)).join('')}
         </div>`]
      : []),
  ].join('');

  return `<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rapport Créa'Book — ${nomSociete}</title></head>
<body style="margin:0;padding:0;">
<div style="${S.wrap}">
<div style="${S.shell}">

  <!-- HEADER -->
  <div style="${S.hdr}">
    <div style="${S.hdrLogo}">CECCA.</div>
    <div style="${S.hdrSub}">Rapport de dossier · Création d'entreprise</div>
    <hr style="border:none;border-top:1px solid rgba(255,255,255,.15);margin:0 0 16px;">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td style="padding:3px 0;width:50%;">
          <div style="${S.hdrLbl}">Date du dossier</div>
          <div style="${S.hdrVal}">${esc(dateStr)}</div>
        </td>
        <td style="padding:3px 0;">
          <div style="${S.hdrLbl}">Conseiller</div>
          <div style="${S.hdrVal}">${esc(body.ownerName || '—')}</div>
        </td>
      </tr>
      <tr>
        <td style="padding:3px 0;">
          <div style="${S.hdrLbl}">Manager responsable</div>
          <div style="${S.hdrVal}">${esc(body.manager || '—')}</div>
        </td>
        <td style="padding:3px 0;">
          <div style="${S.hdrLbl}">Entité</div>
          <div style="${S.hdrVal}">${esc(entite)}</div>
        </td>
      </tr>
    </table>
    <div style="${S.chip}">${esc(entite)} — ${esc(montant)}</div>
  </div>

  <!-- BODY -->
  <div style="${S.body}">

    ${sectionTitle('Société')}
      ${infoTable([
        ['Dénomination sociale', soc.nom],
        ['Forme juridique',      soc.forme],
        ['Capital social',       soc.capital ? soc.capital + ' €' : ''],
        ['Montant nominal / part', soc.montant_nominal ? soc.montant_nominal + ' €' : ''],
        ['Objet social',         soc.objet],
        ['Activité',             soc.activite],
        ['Date de début',        soc.date_debut],
        ['Siège social',         siege],
        ['Banque',               soc.banque_nom],
        ['Type de parcours',     soc.type_parcours],
      ])}
    </div>

    ${sectionTitle('Domiciliation de la société')}
      ${infoTable(hbgRows.map(([l, v]) => [l, v]))}
    </div>

    ${personsHtml}

    ${socDocList.length ? `
    ${sectionTitle('Documents de la société')}
      ${docChips(socDocList)}
    </div>` : ''}

    ${isInternal ? buildFileLinksSection(body) : ''}

  </div>

  <!-- MONTANT -->
  <div style="${S.montBar}">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td>
          <div style="${S.hdrLbl}">Honoraires ${esc(entite)}</div>
          <div style="font-size:24px;font-weight:800;color:#fff;margin-top:4px;">${esc(montant)}</div>
        </td>
        <td style="text-align:right;border-left:1px solid rgba(255,255,255,.18);padding-left:24px;">
          <div style="${S.hdrLbl}">Virement — LCL</div>
          <div style="font-family:'Courier New',monospace;font-size:11.5px;color:rgba(255,255,255,.9);margin-top:4px;">${esc(iban)}</div>
          <div style="font-size:10px;color:rgba(255,255,255,.5);margin-top:3px;">BIC CRLYFRPPXXX · Bénéficiaire : ${esc(benef)}</div>
        </td>
      </tr>
    </table>
  </div>

  <!-- FOOTER -->
  <div style="${S.foot}">
    Rapport généré automatiquement par <strong style="color:#7A1F30;">Créa'Book</strong> · <strong style="color:#7A1F30;">CECCA</strong> —
    Document strictement confidentiel, à usage interne uniquement.
  </div>

</div>
</div>
</body></html>`;
}

async function sendRapport(body, dealId) {
  if (!resendClient) return;
  try {
    const soc    = body.societe || {};
    const entity = body.entity  || 'cecca';
    const entite = entity === 'cecca_etoile' ? 'Cecca Étoile' : 'Cecca';
    const montant = (soc.type_parcours || '') === 'sci_scpi' ? '2 160 €' : '900 €';
    const nomSoc = soc.nom || 'Nouvelle société';
    const now     = new Date();
    const dateStr = now.toLocaleDateString('fr-FR', { day:'2-digit', month:'long', year:'numeric' })
                  + ' à ' + now.toLocaleTimeString('fr-FR', { hour:'2-digit', minute:'2-digit' });
    const subject = `[Créa'Book] Nouveau dossier — ${nomSoc} — ${entite} ${montant}${dealId ? ' · Deal #' + dealId : ''}`;

    // ── Email 1 : client ──────────────────────────────────────────────────────
    const cpKey = body.contactPrincipalKey || '';
    let clientEmail = '';
    if (cpKey) {
      const matchA = cpKey.match(/^a(\d+)$/);
      const matchN = cpKey.match(/^n(\d+)$/);
      if (matchA) clientEmail = ((body.mandatairesAssoc    || [])[parseInt(matchA[1])] || {}).email || '';
      if (matchN) clientEmail = ((body.mandatairesNonAssoc || [])[parseInt(matchN[1])] || {}).email || '';
    }
    if (!clientEmail) {
      for (const p of (body.mandatairesAssoc || [])) {
        if (p.email) { clientEmail = p.email; break; }
      }
    }

    if (clientEmail) {
      const htmlClient = buildRapportHTML(body, dateStr, false);
      const r1 = await resendClient.emails.send({
        from: RESEND_FROM, to: [clientEmail], subject, html: htmlClient,
      });
      console.log('[resend] Email client envoyé à', clientEmail, '| id:', r1.data && r1.data.id);
    } else {
      console.warn('[resend] Email client : aucune adresse client trouvée');
    }

    // ── Email 2 : équipe interne (pôle juridique + owner/collaborateur) ────────
    const internalSet = new Set();

    // Pôle juridique
    const juridique = entity === 'cecca_etoile' ? RESEND_JURIDIQUE_ETOILE : RESEND_JURIDIQUE_CECCA;
    if (juridique) juridique.split(',').map(e => e.trim()).filter(Boolean).forEach(e => internalSet.add(e));

    // Owner (collaborateur sélectionné à l'étape 1)
    if (body.ownerId) {
      const ownerEmail = OWNERS_EMAIL_BY_ID[String(body.ownerId)];
      if (ownerEmail) internalSet.add(ownerEmail);
    }

    // Manager responsable
    if (body.manager) {
      const managerId = OWNERS_BY_NAME[(body.manager || '').trim().toUpperCase()];
      if (managerId) {
        const mgrEmail = OWNERS_EMAIL_BY_ID[String(managerId)];
        if (mgrEmail) internalSet.add(mgrEmail);
      }
    }

    const toInternal = [...internalSet].filter(Boolean);
    if (toInternal.length) {
      const htmlInternal = buildRapportHTML(body, dateStr, true);
      const r2 = await resendClient.emails.send({
        from: RESEND_FROM, to: toInternal, subject, html: htmlInternal,
      });
      console.log('[resend] Email interne envoyé à', toInternal.join(', '), '| id:', r2.data && r2.data.id);
    } else {
      console.warn('[resend] Email interne : aucun destinataire interne trouvé');
    }

  } catch (e) {
    console.error('[resend] Erreur envoi rapport :', e.message);
  }
}

// ── HubSpot helpers ───────────────────────────────────────────────────────────

function s(v) { return typeof v === 'string' ? v.trim() : ''; }

const REGIME_MAP = {
  'célibataire':                        'celibataire',
  'marié(e) — communauté légale':       'marie_communaute',
  'marié(e) — séparation de biens':     'marie_separation',
  'marié(e) — participation aux acquêts': 'marie_participation',
  'marié(e) — communauté universelle':  'marie_universelle',
  'pacsé(e) — indivision':             'pacse_indivision',
  'pacsé(e) — séparation':             'pacse_separation',
  'divorcé(e)':                         'divorce',
  'veuf / veuve':                       'veuf',
};
function toRegimeVal(label) {
  if (!label) return null;
  return REGIME_MAP[label.toLowerCase().trim()] || label;
}

function ddmmyyyyToTs(str) {
  if (!str) return null;
  const parts = str.split('/');
  if (parts.length !== 3) return null;
  const ts = new Date(parseInt(parts[2]), parseInt(parts[1]) - 1, parseInt(parts[0])).getTime();
  return ts > 0 ? ts : null;
}

// ════════════════════════════════════════════════════════════════════════════
//  MAPPING : clé document Créabook  →  propriété HubSpot (URL fichier)
//  Pour corriger un nom de propriété, modifiez uniquement la valeur à droite.
// ════════════════════════════════════════════════════════════════════════════

const DOC_MAPPING_PP = {
  cni:                      'carte_didentite',
  domicile:                 'cb_doc_domicile_dirigeant',
  vitale:                   'cb_doc_vitale_dirigeant',
  livret:                   'cb_doc_livret_famille',
  diplome:                  'cb_doc_diplome_dirigeant',
  attestation_hbg:          'cb_doc_attestation_hebergement',
  cni_hbg:                  'cb_doc_cni_hebergeur',
  domicile_hbg:             'cb_doc_domicile_hebergeur',
  attestation_domiciliation:'cb_doc_attestation_domiciliation',
};

const DOC_MAPPING_PM_RL = {
  pm_cni_rl:     'carte_didentite',
  pm_cni_rp:     'cb_doc_cni_representant_permanent',
  pm_domicile_rp:'cb_doc_domicile_representant_permanent',
};

const DOC_MAPPING_PM_COMPANY = {
  pm_kbis: 'kbis_de_lentreprise',
  pm_rbe:  'cb_doc_rbe',
};

async function hs(method, path, data) {
  const opts = {
    method,
    headers: { Authorization: `Bearer ${HUBSPOT_TOKEN}`, 'Content-Type': 'application/json' },
  };
  if (data !== null) opts.body = JSON.stringify(data);
  const res = await fetch(`https://api.hubapi.com${path}`, opts);
  return { code: res.status, data: await res.json() };
}

function applyDocUrls(props, fileDocs, mapping) {
  for (const [docKey, hsProp] of Object.entries(mapping)) {
    const url = (fileDocs || {})[docKey];
    if (url) props[hsProp] = url;
  }
}

async function createContactPP(d) {
  const p = {};
  if (s(d.prenom))      p.firstname              = s(d.prenom);
  if (s(d.nom))         p.lastname               = s(d.nom);
  if (s(d.email))       p.email                  = s(d.email);
  if (s(d.phone))       p.mobilephone            = s(d.phone);
  if (s(d.adresse))     p.address                = s(d.adresse);
  if (s(d.cp))          p.zip                    = s(d.cp);
  if (s(d.ville))       p.city                   = s(d.ville);
  if (s(d.nationalite)) p.cb_nationalite         = s(d.nationalite);
  if (s(d.num_secu))    p.cb_num_secu            = s(d.num_secu);
  if (s(d.profession))  p.cb_profession          = s(d.profession);
  const regVal = toRegimeVal(s(d.regime));
  if (regVal)           p.cb_regime_matrimonial  = regVal;
  if (s(d.role))        p.cb_role                = s(d.role);
  if (s(d.nb_parts))    p.cb_nb_parts            = s(d.nb_parts);
  if (s(d.apport_num))  p.cb_apport_numeraire    = s(d.apport_num);
  if (s(d.apport_nat))  p.cb_apport_nature       = s(d.apport_nat);
  if (s(d.apport_ind))  p.cb_apport_industrie    = s(d.apport_ind);
  p.cb_acre          = d.acre ? 'oui' : 'non';
  p.cb_type_personne = 'Personne Physique';
  p.cb_source        = 'Créabook';
  p.lifecyclestage   = 'customer';
  const ddn = ddmmyyyyToTs(d.ddn);
  if (ddn) p.date_of_birth = ddn;
  applyDocUrls(p, d.fileDocs,DOC_MAPPING_PP);
  const r = await hs('POST', '/crm/v3/objects/contacts', { properties: p });
  if (r.code < 300) return r.data.id || null;
  // 409 = contact déjà existant → patch avec nos données
  if (r.code === 409) {
    const existingId = (r.data.message || '').match(/Existing ID:\s*(\d+)/)?.[1];
    if (existingId) {
      const pr = await hs('PATCH', `/crm/v3/objects/contacts/${existingId}`, { properties: p });
      if (pr.code < 300) return existingId;
      console.error('[createContactPP] patch échec', pr.code, JSON.stringify(pr.data).slice(0, 300));
    }
  }
  console.error('[createContactPP] échec', r.code, JSON.stringify(r.data).slice(0, 500));
  return null;
}

async function createContactPM(d) {
  const p = {};
  if (s(d.pm_rl_prenom))  p.firstname   = s(d.pm_rl_prenom);
  if (s(d.pm_rl_nom))     p.lastname    = s(d.pm_rl_nom);
  if (s(d.pm_rl_email))   p.email       = s(d.pm_rl_email);
  if (s(d.pm_rl_tel))     p.mobilephone = s(d.pm_rl_tel);
  if (s(d.pm_rl_qualite)) p.cb_role     = s(d.pm_rl_qualite);
  p.cb_type_personne = 'Personne Morale — Représentant Légal';
  p.cb_source        = 'Créabook';
  p.lifecyclestage   = 'customer';
  applyDocUrls(p, d.fileDocs,DOC_MAPPING_PM_RL);
  const r = await hs('POST', '/crm/v3/objects/contacts', { properties: p });
  if (r.code < 300) return r.data.id || null;
  if (r.code === 409) {
    const existingId = (r.data.message || '').match(/Existing ID:\s*(\d+)/)?.[1];
    if (existingId) {
      const pr = await hs('PATCH', `/crm/v3/objects/contacts/${existingId}`, { properties: p });
      if (pr.code < 300) return existingId;
    }
  }
  console.error('[createContactPM] échec', r.code, JSON.stringify(r.data).slice(0, 300));
  return null;
}

async function createCompanyPM(d) {
  const p = {};
  p.name = s(d.pm_denom) || 'Société PM';
  if (s(d.pm_forme))   p.forme_juridique_pappers = s(d.pm_forme);
  if (s(d.pm_capital)) p.capital_pappers         = s(d.pm_capital);
  if (s(d.pm_siren))   p.siren_pappers           = s(d.pm_siren);
  if (s(d.pm_rcs))     p.cb_rcs_pappers = s(d.pm_rcs);
  if (s(d.pm_tel))     p.phone          = s(d.pm_tel);
  if (s(d.pm_adresse)) p.address        = s(d.pm_adresse);
  if (s(d.pm_cp))      p.zip            = s(d.pm_cp);
  if (s(d.pm_ville))   p.city           = s(d.pm_ville);
  if (s(d.pm_pays))    p.country        = s(d.pm_pays);
  p.cb_source      = 'Créabook';
  p.lifecyclestage = 'customer';
  applyDocUrls(p, d.fileDocs, DOC_MAPPING_PM_COMPANY);

  // Si SIREN fourni, chercher une fiche existante pour éviter les doublons
  if (s(d.pm_siren)) {
    const search = await hs('POST', '/crm/v3/objects/companies/search', {
      filterGroups: [{ filters: [{ propertyName: 'siren_pappers', operator: 'EQ', value: s(d.pm_siren) }] }],
      properties: ['hs_object_id'],
      limit: 1,
    });
    if (search.code === 200 && (search.data.results || []).length > 0) {
      const existingId = search.data.results[0].id;
      console.log('[createCompanyPM] SIREN trouvé, PATCH sur', existingId);
      const pr = await hs('PATCH', `/crm/v3/objects/companies/${existingId}`, { properties: p });
      return pr.code < 300 ? existingId : null;
    }
  }

  const r = await hs('POST', '/crm/v3/objects/companies', { properties: p });
  return r.code < 300 ? (r.data.id || null) : null;
}

async function associateToCompany(contactId, companyId) {
  await hs('PUT', `/crm/v4/objects/contacts/${contactId}/associations/default/companies/${companyId}`, null);
}

async function associateCompanies(childId, parentId) {
  await hs('PUT', `/crm/v4/objects/companies/${childId}/associations/default/companies/${parentId}`, null);
}

async function createNoteWithFiles(contactId, noteBody, fileIds) {
  const attachments = fileIds.filter(Boolean).map(id => ({ id: parseInt(id) }));
  const payload = {
    engagement:   { type: 'NOTE', timestamp: Date.now() },
    associations: { contactIds: [parseInt(contactId)] },
    metadata:     { body: noteBody },
  };
  if (attachments.length) payload.attachments = attachments;
  await hs('POST', '/engagements/v1/engagements', payload);
}

async function createNoteOnCompany(companyId, noteBody, fileIds) {
  const attachments = fileIds.filter(Boolean).map(id => ({ id: parseInt(id) }));
  const payload = {
    engagement:   { type: 'NOTE', timestamp: Date.now() },
    associations: { companyIds: [parseInt(companyId)] },
    metadata:     { body: noteBody },
  };
  if (attachments.length) payload.attachments = attachments;
  await hs('POST', '/engagements/v1/engagements', payload);
}

async function createNoteOnDeal(dealId, noteBody, fileIds) {
  const attachments = fileIds.filter(Boolean).map(id => ({ id: parseInt(id) }));
  const payload = {
    engagement:   { type: 'NOTE', timestamp: Date.now() },
    associations: { dealIds: [parseInt(dealId)] },
    metadata:     { body: noteBody },
  };
  if (attachments.length) payload.attachments = attachments;
  await hs('POST', '/engagements/v1/engagements', payload);
}

// ── Frontend ──────────────────────────────────────────────────────────────────

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => console.log(`creabook-api listening on :${PORT}`));
