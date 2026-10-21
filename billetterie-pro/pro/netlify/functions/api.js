const crypto = require('crypto');
const KEY = process.env.STRIPE_SECRET_KEY, SECRET = process.env.TICKET_SECRET, PASS = process.env.SCAN_PASSWORD;
const FREE_MAX = Number(process.env.FREE_MAX || 30); // nombre max de billets gratuits
const json = (s, o) => ({ statusCode: s, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(o) });
const sign = id => crypto.createHmac('sha256', SECRET).update(id).digest('hex').slice(0, 16);
const same = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const enc = o => Object.keys(o).map(k => encodeURIComponent(k) + '=' + encodeURIComponent(o[k])).join('&');
const ID = /^(cs_(test|live)|cus)_[A-Za-z0-9]+$/;
async function stripe(path, body) {
  const r = await fetch('https://api.stripe.com/v1/' + path, {
    method: body ? 'POST' : 'GET',
    headers: Object.assign({ Authorization: 'Bearer ' + KEY }, body ? { 'Content-Type': 'application/x-www-form-urlencoded' } : {}),
    body
  });
  return { ok: r.ok, d: await r.json() };
}
const ticketName = s => (s.amount_total === 0 ? 'Gratuit' : s.amount_total === 700 ? 'Prévente' : 'Normale');
const isPaid = s => s.payment_status === 'paid' || s.payment_status === 'no_payment_required';

// Charge un billet : paiement Stripe (cs_...) ou billet gratuit (cus_...)
async function load(id) {
  if (id.startsWith('cus_')) {
    const r = await stripe('customers/' + id);
    const d = r.d;
    if (!r.ok || d.deleted || !d.metadata || d.metadata.type !== 'free') return null;
    return { name: d.name || '', email: d.email || '', ticket: 'Gratuit', amount: 0, used: d.metadata.used, path: 'customers/' };
  }
  const r = await stripe('checkout/sessions/' + id);
  if (!r.ok || !isPaid(r.d)) return r.ok ? { pending: true } : null;
  const c = r.d.customer_details || {};
  return { name: c.name || '', email: c.email || '', ticket: ticketName(r.d), amount: r.d.amount_total / 100, used: r.d.metadata && r.d.metadata.used, path: 'checkout/sessions/' };
}
function split(code) {
  const i = code.lastIndexOf('.'), id = code.slice(0, i), sig = code.slice(i + 1);
  return (i > 0 && ID.test(id) && same(sig, sign(id))) ? id : null;
}

exports.handler = async (event) => {
  if (!KEY || !SECRET) return json(500, { error: 'Serveur mal configuré.' });
  const q = event.queryStringParameters || {};
  let body = {};
  try { body = JSON.parse(event.body || '{}'); } catch (e) {}

  // 1) Page « merci » : renvoie les infos du billet (paiement vérifié ou billet gratuit signé)
  if (q.action === 'ticket') {
    const id = q.code ? split(q.code) : (ID.test(q.session_id || '') ? q.session_id : null);
    if (!id) return json(400, { error: 'Lien invalide.' });
    const t = await load(id);
    if (!t) return json(404, { error: 'Billet introuvable.' });
    if (t.pending) return json(402, { error: 'Paiement non confirmé. Réessaie dans une minute.' });
    return json(200, { code: id + '.' + sign(id), name: t.name, email: t.email, ticket: t.ticket, amount: t.amount });
  }

  // 2) Billet gratuit : crée un « client » Stripe marqué gratuit (1 par e-mail, nombre limité)
  if (q.action === 'free' && event.httpMethod === 'POST') {
    const name = (String(body.prenom || '').trim() + ' ' + String(body.nom || '').trim()).trim().slice(0, 80);
    const email = String(body.email || '').trim().toLowerCase().slice(0, 120);
    if (!name || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json(400, { error: 'Nom ou e-mail invalide.' });
    const ex = await stripe('customers?limit=10&email=' + encodeURIComponent(email));
    const old = ex.ok && ex.d.data.find(c => c.metadata && c.metadata.type === 'free');
    if (old) return json(200, { code: old.id + '.' + sign(old.id) });
    const cnt = await stripe('customers/search?limit=1&expand[]=total_count&query=' + encodeURIComponent("metadata['type']:'free'"));
    if (!cnt.ok) return json(500, { error: 'Réservation indisponible pour le moment.' });
    if (cnt.d.total_count >= FREE_MAX) return json(409, { error: 'Il n’y a plus de billets gratuits.' });
    const c = await stripe('customers', enc({ name, email, 'metadata[type]': 'free' }));
    if (!c.ok) return json(500, { error: 'Réservation impossible. Réessaie.' });
    return json(200, { code: c.d.id + '.' + sign(c.d.id) });
  }

  // 3) Scan à l’entrée : valide le QR code et marque le billet comme utilisé
  if (q.action === 'scan' && event.httpMethod === 'POST') {
    if (!PASS || !same(String(event.headers['x-password'] || ''), PASS)) return json(401, { error: 'Mot de passe incorrect.' });
    const id = split(String(body.code || ''));
    const t = id && await load(id);
    if (!t || t.pending) return json(200, { status: 'invalid' });
    const info = { name: t.name, ticket: t.ticket };
    if (t.used) return json(200, Object.assign({ status: 'used', usedAt: t.used }, info));
    await stripe(t.path + id, 'metadata[used]=' + encodeURIComponent(new Date().toISOString()));
    return json(200, Object.assign({ status: 'ok' }, info));
  }
  return json(400, { error: 'Requête invalide.' });
};
