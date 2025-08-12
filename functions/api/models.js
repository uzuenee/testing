export async function onRequestGet(context) {
    try {
      const { request, env } = context;
      const ok = checkBasicAuth(request, env);
      if (!ok) {
        return json({ error: 'Unauthorized' }, 401, { 'WWW-Authenticate': 'Basic realm="Private"' });
      }
  
      const res = await fetch('https://api.openai.com/v1/models', {
        headers: { 'Authorization': `Bearer ${env.OPENAI_API_KEY}` }
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const msg = (data && (data.error?.message || data.error || data.message)) || `OpenAI error ${res.status}`;
        return json({ error: msg }, res.status);
      }
  
      // Filter to chat-capable models (heuristic)
      const all = Array.isArray(data.data) ? data.data : [];
      const ids = all
        .map(m => m.id)
        .filter(id => typeof id === 'string')
        .filter(id => id.startsWith('gpt-') || id.startsWith('o'))
        .sort((a, b) => a.localeCompare(b));
  
      return json({ models: [...new Set(ids)] });
    } catch (err) {
      return json({ error: err.message || String(err) }, 500);
    }
  }
  
  function checkBasicAuth(request, env) {
    const header = request.headers.get('authorization') || '';
    if (!header.startsWith('Basic ')) return false;
    try {
      const decoded = atob(header.slice(6));
      const idx = decoded.indexOf(':');
      const user = decoded.slice(0, idx);
      const pass = decoded.slice(idx + 1);
      return (user === (env.APP_USERNAME || 'your-username')) && (pass === (env.APP_PASSWORD || 'your-password'));
    } catch {
      return false;
    }
  }
  function json(obj, status = 200, headers = {}) {
    return new Response(JSON.stringify(obj), {
      status,
      headers: { 'Content-Type': 'application/json', ...headers }
    });
  }