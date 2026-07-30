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

const app  = express();
const PORT = 8080;

const HUBSPOT_TOKEN  = process.env.HUBSPOT_TOKEN;
const TOKEN_SECRET   = process.env.TOKEN_SECRET;

if (!HUBSPOT_TOKEN) throw new Error('HUBSPOT_TOKEN manquant');
if (!TOKEN_SECRET)  throw new Error('TOKEN_SECRET manquant');

// ── Cache HubSpot pipeline + owners ──────────────────────────────────────────

let DEAL_PIPELINE_ID      = null;
let DEAL_STAGE_ID         = null;
let OWNERS_BY_NAME        = {};
let OWNERS_LIST           = [];
let MANAGER_SYNCHRO_VALID = new Set();
let CHEF_SYNCHRO_VALID    = new Set();

async function initHubSpotCache() {
  try {
    const pRes  = await fetch('https://api.hubapi.com/crm/v3/pipelines/deals', {
      headers: { Authorization: `Bearer ${HUBSPOT_TOKEN}` },
    });
    const pData = await pRes.json();
    const pipe  = (pData.results || []).find(p => p.label.trim().toLowerCase() === "création d'entreprise");
    if (pipe) {
      DEAL_PIPELINE_ID = pipe.id;
      const first = (pipe.stages || []).sort((a, b) => a.displayOrder - b.displayOrder)[0];
      if (first) DEAL_STAGE_ID = first.id;
    }
    console.log(`Pipeline deal : ${DEAL_PIPELINE_ID} / étape : ${DEAL_STAGE_ID}`);
  } catch (e) {
    console.error('initHubSpotCache pipelines :', e.message);
  }

  try {
    const oRes  = await fetch('https://api.hubapi.com/crm/v3/owners/?limit=100', {
      headers: { Authorization: `Bearer ${HUBSPOT_TOKEN}` },
    });
    const oData = await oRes.json();
    (oData.results || []).forEach(o => {
      const full = `${o.firstName || ''} ${o.lastName || ''}`.trim();
      if (full) {
        OWNERS_BY_NAME[full.toUpperCase()] = o.id;
        if (!OWNERS_LIST.find(x => x.id === o.id)) OWNERS_LIST.push({ name: full, id: o.id });
      }
    });
    OWNERS_LIST.sort((a, b) => a.name.localeCompare(b.name, 'fr'));
    console.log(`Owners chargés : ${OWNERS_LIST.length}`);
  } catch (e) {
    console.error('initHubSpotCache owners :', e.message);
  }

  try {
    const pRes  = await fetch('https://api.hubapi.com/crm/v3/properties/deals/manager_synchro', {
      headers: { Authorization: `Bearer ${HUBSPOT_TOKEN}` },
    });
    const pData = await pRes.json();
    (pData.options || []).forEach(o => MANAGER_SYNCHRO_VALID.add(o.value));

    const cRes  = await fetch('https://api.hubapi.com/crm/v3/properties/deals/chef_de_mission_synchro', {
      headers: { Authorization: `Bearer ${HUBSPOT_TOKEN}` },
    });
    const cData = await cRes.json();
    (cData.options || []).forEach(o => CHEF_SYNCHRO_VALID.add(o.value));
    console.log(`manager_synchro options : ${MANAGER_SYNCHRO_VALID.size}`);
  } catch (e) {
    console.error('initHubSpotCache synchro options :', e.message);
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

// ── POST /draft — collab saves partial state ──────────────────────────────────

app.post('/draft', async (req, res) => {
  const body = req.body;
  if (!checkToken(body.token || '')) return res.status(403).json({ error: 'Token invalide' });

  const state  = body.state || {};
  const hsF    = state.hsFields || {};

  const draftManagerName = s(hsF.cb_manager);
  const draftEtoile      = ['SIMBOU DANFAKHA','YANN POINLOUP','MATEUS SOUTELO','JULIEN DECLERCQ'].includes(draftManagerName.toUpperCase());
  const draftEntite      = draftEtoile ? 'Cecca Étoile' : 'Cecca';

  const companyProps = { name: (s(hsF.cb_denomination_sociale) || 'Brouillon') + ' (En création)', siren_pappers: '999999999' };
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
  if (draftManagerName)                companyProps.cb_manager              = draftManagerName;
  companyProps.cb_entite      = draftEntite;
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
  const ownerId     = managerName ? (OWNERS_BY_NAME[managerName.toUpperCase()] || null) : null;
  const entiteLabel = body.entity === 'cecca_etoile' ? 'Cecca Étoile' : 'Cecca';
  const entiteEnum  = body.entity === 'cecca_etoile' ? 'CECCA Étoile' : 'CECCA';

  console.log('[submit] ownerId pour', managerName, ':', ownerId);

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
    lifecyclestage:       'Client',        // valeur interne HubSpot (confirmée par l'utilisateur)
    cb_source:            'Créabook',
    // Manager / entité
    cb_entite:            entiteLabel,
    entite:               entiteEnum,
  };

  // Champs optionnels issus du mapping
  for (const [crField, hsField] of Object.entries(companyMapping)) {
    if (crField === 'nom') continue; // déjà traité ci-dessus
    const v = s(soc[crField]);
    if (v) companyProps[hsField] = v;
  }

  if (managerName) companyProps.cb_manager = managerName;
  if (managerName && MANAGER_SYNCHRO_VALID.has(managerName)) companyProps.manager = managerName;

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
    amount:             body.entity === 'cecca_etoile' ? '2160' : '900',
    // Pipeline (IDs chargés au démarrage)
    pipeline:           DEAL_PIPELINE_ID || 'default',
    dealstage:          DEAL_STAGE_ID    || 'appointmentscheduled',
    // Manager / entité / source
    cb_source:          'Créabook',
    source:             'Créabook',
    cb_entite:          body.entity || 'cecca',
  };

  if (ownerId)      dealProps.hubspot_owner_id = ownerId;
  if (managerName)  dealProps.cb_manager       = managerName;

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

  } catch(e) {
    console.error('[submit] exception non gérée :', e);
    res.status(500).json({ ok: false, error: e.message, errors: [e.message] });
  }
});

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

async function getFileUrl(fileId) {
  if (!fileId) return null;
  const r = await hs('GET', `/files/v3/files/${fileId}`, null);
  return r.code < 300 ? (r.data.url || null) : null;
}

async function applyDocUrls(props, fileDocs, mapping) {
  for (const [docKey, hsProp] of Object.entries(mapping)) {
    const fileId = (fileDocs || {})[docKey];
    if (!fileId) continue;
    const url = await getFileUrl(fileId);
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
  await applyDocUrls(p, d.fileDocs, DOC_MAPPING_PP);
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
  await applyDocUrls(p, d.fileDocs, DOC_MAPPING_PM_RL);
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
  await applyDocUrls(p, d.fileDocs, DOC_MAPPING_PM_COMPANY);
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
