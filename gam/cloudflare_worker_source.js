/**
 * GAM — Cloudflare Email Worker (inbound → gam.api.receive_email_webhook)
 *
 * Wire-up (Cloudflare dashboard → Email → Email Routing):
 *   1. Enable Email Routing on the domain that owns the `webhook_email` inbox
 *      (the address configured in `GAM Webhook Config`).
 *   2. Add a routing rule:  catch-all (or the exact address) → "Send to a Worker"
 *      → select this deployed worker.
 *
 * Worker bindings (set via `wrangler secret put` or the dashboard):
 *   GAM_WEBHOOK_URL     https://<your-public-host>/api/method/gam.api.receive_email_webhook
 *   GAM_WEBHOOK_SECRET   the value stored in `GAM Webhook Config.webhook_secret`
 *
 * Requires: `npm install postal-mime` (MIME parser that runs in the Workers
 * runtime). The parsed plain-text body + subject are regex-matched server-side
 * against the seeded Code Patterns (STEAM / BATTLENET / POE).
 *
 * Payload posted to Frappe (matches gam.api.receive_email_webhook contract):
 *   { email_account, from, subject, body, html, message_id, received_at, raw }
 */
import PostalMime from 'postal-mime'

/** Strip HTML tags for a best-effort plain-text body fallback. */
function stripHtml(html) {
  if (!html) return ''
  return html
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&/gi, '&')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(parseInt(n, 10)))
    .replace(/\s+/g, ' ')
    .trim()
}

export default {
  async email(message, env) {
    let responseStatus = 200
    try {
      // `message.raw` is a ReadableStream of the full RFC 5322 message.
      const rawBuf = await new Response(message.raw).arrayBuffer()
      const parsed = await PostalMime.parse(rawBuf)

      const toAddr = (message.to || parsed.to?.text || '').trim()
      const dateHeader = message.headers.get('date')

      const payload = {
        email_account: toAddr,
        from: parsed.from?.text || message.from || '',
        subject: parsed.subject || '',
        body: parsed.text || stripHtml(parsed.html) || '',
        html: parsed.html || '',
        message_id: message.headers.get('message-id') || '',
        received_at: dateHeader || new Date().toISOString(),
        // Keep a short snippet of the raw text as a debugging aid (backend caps @ 5000).
        raw: '',
      }

      const webhookUrl = env.GAM_WEBHOOK_URL
      const webhookSecret = env.GAM_WEBHOOK_SECRET
      if (!webhookUrl || !webhookSecret) {
        console.error('GAM worker missing GAM_WEBHOOK_URL / GAM_WEBHOOK_SECRET binding')
        responseStatus = 500
      } else {
        const res = await fetch(webhookUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Webhook-Secret': webhookSecret,
          },
          body: JSON.stringify(payload),
        })
        responseStatus = res.status
        if (!res.ok) {
          console.error(`GAM webhook non-OK: HTTP ${res.status}`)
        }
      }
    } catch (err) {
      console.error('GAM worker error', err)
      responseStatus = 500
    }

    // Reject the message (Cloudflare treats this as a permanent failure / bounce)
    // only on hard errors — a 4xx/5xx from Frappe is retried by rejecting too.
    if (responseStatus >= 500) {
      message.setReject(`GAM webhook failed: HTTP ${responseStatus}`)
    }
  },
}
