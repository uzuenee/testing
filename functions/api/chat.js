export async function onRequestPost(context) {
    try {
      const { request, env } = context;
  
      // Basic Auth (single user). Set APP_USERNAME and APP_PASSWORD in environment.
      const ok = checkBasicAuth(request, env);
      if (!ok) {
        return json({ error: 'Unauthorized' }, 401, { 'WWW-Authenticate': 'Basic realm="Private"' });
      }
  
      const body = await request.json();
      const {
        model,
        messages = [],
        systemPrompt = '',
        settings = {},
        reasoning = 'medium',
        verbosity = 'normal'
      } = body || {};
  
      const chosenModel = (typeof model === 'string' && model.trim()) ? model.trim() : 'gpt-4o-mini';
  
      // Build system guidance using "reasoning" and "verbosity"
      const extraLines = [];
      if (reasoning === 'low') extraLines.push('Spend minimal steps on internal reasoning; answer quickly and directly.');
      else if (reasoning === 'medium') extraLines.push('Reason adequately to ensure correctness, but keep it efficient.');
      else if (reasoning === 'high') extraLines.push('Take time to reason carefully. Consider edge cases and verify steps.');
      if (verbosity === 'brief') extraLines.push('Be brief. Prefer short answers unless more detail is requested.');
      else if (verbosity === 'normal') extraLines.push('Be clear and to the point. Provide detail where useful.');
      else if (verbosity === 'detailed') extraLines.push('Be thorough and detailed. Provide step-by-step explanations and examples.');
  
      const systemText = [systemPrompt || 'You are a helpful assistant.', ...extraLines].join('\n');
  
      // Prepare messages for OpenAI Chat Completions
      const msgs = [{ role: 'system', content: systemText }];
  
      for (const m of messages) {
        if (!m || !m.role || typeof m.content !== 'string') continue;
        if (m.role !== 'user' && m.role !== 'assistant' && m.role !== 'system') continue;
        // Avoid duplicating system: user history may already include one; but we enforce our own system at top
        if (m.role === 'system') continue;
        msgs.push({ role: m.role, content: m.content });
      }
  
      // Apply defaults and sanitize
      const temperature = clampNum(settings.temperature, 0, 2, 0.7);
      const top_p = clampNum(settings.top_p, 0, 1, 1.0);
      const max_tokens = clampNum(settings.max_tokens, 64, 8192, 1024);
      const presence_penalty = clampNum(settings.presence_penalty, -2, 2, 0.0);
      const frequency_penalty = clampNum(settings.frequency_penalty, -2, 2, 0.0);
  
      const openaiRes = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.OPENAI_API_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: chosenModel,
          messages: msgs,
          temperature,
          top_p,
          max_tokens,
          presence_penalty,
          frequency_penalty,
          n: 1,
          // seed: 42 // optional: uncomment for more consistent outputs
        })
      });
  
      const data = await openaiRes.json().catch(() => ({}));
      if (!openaiRes.ok) {
        const msg = (data && (data.error?.message || data.error || data.message)) || `OpenAI error ${openaiRes.status}`;
        return json({ error: msg }, openaiRes.status);
      }
  
      const choice = data.choices?.[0];
      const reply = choice?.message?.content || '';
      const usage = data.usage || null;
  
      return json({ reply, usage, model: chosenModel });
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
  
  function clampNum(v, min, max, dflt) {
    const n = Number(v);
    if (Number.isFinite(n)) return Math.min(max, Math.max(min, n));
    return dflt;
  }
  
  function json(obj, status = 200, headers = {}) {
    return new Response(JSON.stringify(obj), {
      status,
      headers: { 'Content-Type': 'application/json', ...headers }
    });
  }