const crypto = require('crypto');
const KEY = process.env.STRIPE_SECRET_KEY, SECRET = process.env.TICKET_SECRET, PASS = process.env.SCAN_PASSWORD;
const json = (s, o) => ({ statusCode: s, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(o) });
const sign = id => crypto.createHmac('sha256', SECRET).update(id).digest('hex').slice(0, 16);
const same = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
async function stripe(path, body) {
  const r = await fetch('https://api.stripe.com/v1/' + path, {
    method: body ? 'POST' : 'GET',
    headers: Object.assign({ Authorization: 'Bearer ' + KEY }, body ? { 'Content-Type': 'application/x-www-form-urlencoded' } : {}),
    body
  });
  return { ok: r.ok, d: await r.json() };
}
const ticketName = s => (s.amount_total === 700 ? 'Prévente' : 'Normale');

exports.handler = async (event) => {
  if (!KEY || !SECRET) return json(500, { error: 'Serveur mal configuré.' });
  const q = event.queryStringParameters || {};

  // 1) Page « merci » : vérifie le paiement et renvoie les infos du billet
  if (q.action === 'ticket') {
    const id = q.session_id || '';
    if (!/^cs_(test|live)_[A-Za-z0-9]+$/.test(id)) return json(400, { error: 'Lien invalide.' });
    const s = await stripe('checkout/sessions/' + id);
    if (!s.ok) return json(404, { error: 'Paiement introuvable.' });
    if (s.d.payment_status !== 'paid') return json(402, { error: 'Paiement non confirmé. Réessaie dans une minute.' });
    const c = s.d.customer_details || {};
    return json(200, { code: id + '.' + sign(id), name: c.name || '', email: c.email || '', ticket: ticketName(s.d), amount: s.d.amount_total / 100 });
  }

  // 2) Scan à l’entrée : valide le QR code et marque le billet comme utilisé
  if (q.action === 'scan' && event.httpMethod === 'POST') {
    if (!PASS || !same(String(event.headers['x-password'] || ''), PASS)) return json(401, { error: 'Mot de passe incorrect.' });
    let code = '';
    try { code = String(JSON.parse(event.body || '{}').code || ''); } catch (e) {}
    const i = code.lastIndexOf('.');
    const id = code.slice(0, i), sig = code.slice(i + 1);
    if (i < 0 || !/^cs_(test|live)_[A-Za-z0-9]+$/.test(id) || !same(sig, sign(id))) return json(200, { status: 'invalid' });
    const s = await stripe('checkout/sessions/' + id);
    if (!s.ok || s.d.payment_status !== 'paid') return json(200, { status: 'invalid' });
    const c = s.d.customer_details || {};
    const info = { name: c.name || '', ticket: ticketName(s.d) };
    if (s.d.metadata && s.d.metadata.used) return json(200, Object.assign({ status: 'used', usedAt: s.d.metadata.used }, info));
    await stripe('checkout/sessions/' + id, 'metadata[used]=' + encodeURIComponent(new Date().toISOString()));
    return json(200, Object.assign({ status: 'ok' }, info));
  }
  return json(400, { error: 'Requête invalide.' });
};
