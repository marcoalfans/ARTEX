---
name: subdomain-takeover
description: "Invoke this skill when the task requires testing for subdomain takeover vulnerabilities under authorized engagement: dangling DNS records (CNAME, NS, A), cloud service takeover (AWS S3, Azure, Heroku, GitHub Pages, Shopify, Fastly, and others), wildcard DNS abuse, stale delegations, and expired third-party service claims. Tools include subfinder, dig, httpx, and manual DNS analysis. A finding is confirmed only when the takeover is demonstrated or the claim mechanism is verified as exploitable."
---

# Subdomain Takeover Testing

This skill covers discovery and verification of subdomain takeover vulnerabilities. A subdomain takeover occurs when a DNS record (usually CNAME) points to a third-party service that the target no longer controls, allowing an attacker to claim that service endpoint and serve content on the target's subdomain. Findings require proof that the service is claimable, not merely that a DNS record exists.

## Boundaries

| Allowed | Prohibited |
|---|---|
| Enumerating subdomains and DNS records for the target domain | Enumerating or testing domains outside authorized scope |
| Verifying dangling CNAME/NS records via DNS resolution | Actually registering or claiming the takeover on production subdomains without explicit approval |
| Claiming a dangling service endpoint on test/staging subdomains with approval | Serving malicious content (phishing, malware) on taken-over subdomains |
| Demonstrating the takeover with a benign proof page | Using taken-over subdomains to bypass same-origin policy against production |
| Reporting the takeover as claimable with evidence (without claiming) | Modifying DNS records belonging to the target |
| Checking expired domain registrations for NS takeover | Registering expired domains without explicit authorization |

## Phase 0: Pre-engagement setup

### 0.1 Scope confirmation

1. Confirm which root domains are in scope (e.g., `target.com`, `target.io`, `target-cdn.net`).
2. Confirm whether actual takeover demonstration is authorized, or only identification and evidence collection.
3. Determine whether the engagement includes wildcard domains and subsidiary domains.

### 0.2 Tool setup

```bash
# Subdomain enumeration
subfinder -version 2>&1 || echo "Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
amass version 2>&1 || echo "Install: go install github.com/owasp-amass/amass/v4/...@latest"

# HTTP probing
httpx -version 2>&1 || echo "Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"

# DNS tools (usually pre-installed)
dig -v 2>&1
host -V 2>&1

# Working directory
mkdir -p work/subdomain-takeover/{dns,http,proofs,enum}
```

## Phase 1: Subdomain enumeration

### 1.1 Passive enumeration

```bash
# subfinder (passive sources: crt.sh, VirusTotal, SecurityTrails, etc.)
subfinder -d target.com -all -o work/subdomain-takeover/enum/subfinder.txt

# amass (passive mode)
amass enum -passive -d target.com -o work/subdomain-takeover/enum/amass.txt

# Certificate transparency logs
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  jq -r '.[].name_value' | sort -u > work/subdomain-takeover/enum/crtsh.txt

# Merge and deduplicate
cat work/subdomain-takeover/enum/*.txt | sort -u > work/subdomain-takeover/enum/all-subdomains.txt
echo "Total unique subdomains: $(wc -l < work/subdomain-takeover/enum/all-subdomains.txt)"
```

### 1.2 DNS record collection

For each subdomain, collect the full DNS record set:

```bash
# Bulk DNS resolution
while read sub; do
  echo "=== $sub ==="
  dig +short CNAME "$sub" 2>/dev/null
  dig +short A "$sub" 2>/dev/null
  dig +short AAAA "$sub" 2>/dev/null
  dig +short NS "$sub" 2>/dev/null
done < work/subdomain-takeover/enum/all-subdomains.txt \
  > work/subdomain-takeover/dns/all-records.txt 2>&1

# Extract CNAME records specifically (primary takeover vector)
while read sub; do
  cname=$(dig +short CNAME "$sub" 2>/dev/null)
  [ -n "$cname" ] && echo "$sub -> $cname"
done < work/subdomain-takeover/enum/all-subdomains.txt \
  > work/subdomain-takeover/dns/cname-records.txt
```

### 1.3 HTTP probing

```bash
# Probe all subdomains for HTTP responses
httpx -l work/subdomain-takeover/enum/all-subdomains.txt \
  -status-code -title -content-length -tech-detect \
  -o work/subdomain-takeover/http/httpx-results.txt

# Look for takeover indicator responses
httpx -l work/subdomain-takeover/enum/all-subdomains.txt \
  -match-string "NoSuchBucket" \
  -match-string "There isn't a GitHub Pages site here" \
  -match-string "herokucdn.com/error-pages" \
  -match-string "The request could not be satisfied" \
  -match-string "CNAME Cross-User Banned" \
  -o work/subdomain-takeover/http/takeover-candidates.txt
```

## Phase 2: Dangling CNAME identification

### 2.1 CNAME resolution chain analysis

For each CNAME record found:

```bash
# Full resolution chain
dig +trace +all sub.target.com

# Check if the CNAME target resolves
dig +short CNAME sub.target.com        # e.g., sub.target.com -> app.heroku.com
dig +short A app.heroku.com            # Does the target resolve?

# NXDOMAIN on the CNAME target = strong takeover candidate
# SERVFAIL = possible NS delegation issue
# No A record but CNAME exists = dangling
```

### 2.2 Fingerprinting the service behind the CNAME

| CNAME target pattern | Service | Takeover possible? |
|---|---|---|
| `*.s3.amazonaws.com` | AWS S3 | Yes, if bucket is unclaimed |
| `*.s3-website-*.amazonaws.com` | AWS S3 website | Yes |
| `*.cloudfront.net` | AWS CloudFront | Yes, if distribution is unclaimed |
| `*.elasticbeanstalk.com` | AWS Elastic Beanstalk | Yes |
| `*.azurewebsites.net` | Azure App Service | Yes |
| `*.blob.core.windows.net` | Azure Blob Storage | Yes |
| `*.cloudapp.azure.com` | Azure VM | Yes |
| `*.trafficmanager.net` | Azure Traffic Manager | Yes |
| `*.herokuapp.com` | Heroku | Yes |
| `*.herokudns.com` | Heroku custom domain | Yes |
| `*.github.io` | GitHub Pages | Yes |
| `*.gitlab.io` | GitLab Pages | Yes |
| `*.shopifycloud.com` | Shopify | Conditional (must be Shopify merchant) |
| `*.ghost.io` | Ghost | Yes |
| `*.wordpress.com` | WordPress.com | Yes |
| `*.pantheonsite.io` | Pantheon | Yes |
| `*.netlify.app` | Netlify | Yes |
| `*.surge.sh` | Surge | Yes |
| `*.bitbucket.io` | Bitbucket Pages | Yes |
| `*.zendesk.com` | Zendesk | Yes |
| `*.helpjuice.com` | HelpJuice | Yes |
| `*.helpscoutdocs.com` | HelpScout | Yes |
| `*.feedpress.me` | FeedPress | Yes |
| `*.freshdesk.com` | Freshdesk | Yes |
| `*.uptimerobot.com` | UptimeRobot | Yes |
| `*.bigcartel.com` | BigCartel | Yes |
| `*.teamwork.com` | Teamwork | Yes |
| `*.cargocollective.com` | Cargo | Yes |
| `*.fastly.net` | Fastly | Yes |
| `*.smugmug.com` | SmugMug | Yes |
| `*.strikingly.com` | Strikingly | Yes |
| `*.webflow.io` | Webflow | Yes |

### 2.3 Verification of dangling state

For each candidate, confirm the CNAME target is unclaimed:

```bash
# S3 bucket
curl -sI "http://BUCKET_NAME.s3.amazonaws.com/" | head -5
# 404 with "NoSuchBucket" = takeover possible
# 403 = bucket exists but is private (not takeover)

# Heroku
curl -sI "https://sub.target.com/"
# "herokucdn.com/error-pages/no-such-app" = takeover possible

# GitHub Pages
curl -sI "https://sub.target.com/"
# 404 with "There isn't a GitHub Pages site here" = takeover possible

# Azure App Service
curl -sI "https://sub.target.com/"
# "*.azurewebsites.net not found" or default Azure 404 = takeover possible

# CloudFront
curl -sI "https://sub.target.com/"
# "The request could not be satisfied" with "Bad request" = possibly takeover
```

## Phase 3: NS delegation takeover

### 3.1 Stale NS delegation

A more critical class of takeover: if a subdomain delegates DNS to nameservers the target no longer controls.

```bash
# Check NS records for subdomains
dig +short NS sub.target.com

# If NS points to a cloud DNS provider (Route53, Azure DNS, GCP Cloud DNS)
# and the hosted zone no longer exists, an attacker can create it

# Check if the NS target responds authoritatively
dig @ns1.example-provider.com sub.target.com SOA

# REFUSED or SERVFAIL from the delegated NS = potential NS takeover
```

### 3.2 NS takeover impact

NS takeover is significantly more dangerous than CNAME takeover:
- Attacker controls ALL DNS records for the subdomain and its children.
- Attacker can issue TLS certificates via DNS-01 challenges.
- Attacker can receive email (MX records), intercept verification flows.
- Attacker controls SPF/DKIM/DMARC for the subdomain.

### 3.3 Expired domain NS takeover

```bash
# Check if the NS domain itself has expired
whois ns1.old-provider.com | grep -iE 'expir|status'

# If the NS domain is expired and available for registration,
# registering it would give control over all zones delegated to it
# DO NOT register without explicit authorization
```

## Phase 4: Cloud service-specific takeover procedures

### 4.1 AWS S3 takeover

**Identification:**
```bash
# CNAME: sub.target.com -> sub.target.com.s3.amazonaws.com
curl -s "http://sub.target.com.s3.amazonaws.com/"
# Response: <Code>NoSuchBucket</Code> = takeover possible
```

**Takeover (with authorization only):**
```bash
# Create the bucket with the exact name
aws s3 mb s3://sub.target.com --region us-east-1

# Enable static website hosting
aws s3 website s3://sub.target.com --index-document index.html

# Upload proof page
echo "<html><body><h1>Subdomain Takeover PoC - [YOUR_ID]</h1></body></html>" > /tmp/index.html
aws s3 cp /tmp/index.html s3://sub.target.com/ --acl public-read

# Verify: https://sub.target.com should now serve your page
curl -s "https://sub.target.com/"

# IMMEDIATELY clean up after proof
aws s3 rm s3://sub.target.com/index.html
aws s3 rb s3://sub.target.com
```

### 4.2 GitHub Pages takeover

**Identification:**
```bash
# CNAME: sub.target.com -> target-org.github.io
curl -sI "https://sub.target.com/"
# 404 with "There isn't a GitHub Pages site here"
```

**Takeover (with authorization only):**
1. Create a GitHub repository named `target-org.github.io` (or the matching org/user pages repo).
2. Add a `CNAME` file containing `sub.target.com`.
3. Enable GitHub Pages in the repository settings.
4. Push a proof `index.html`.

### 4.3 Heroku takeover

**Identification:**
```bash
# CNAME: sub.target.com -> something.herokuapp.com or herokudns.com
curl -sI "https://sub.target.com/"
# "No such app" error page
```

**Takeover (with authorization only):**
```bash
heroku create --app NAME_MATCHING_CNAME
heroku domains:add sub.target.com --app NAME
# Deploy proof page
```

### 4.4 Azure takeover

**Identification:**
```bash
# CNAME: sub.target.com -> something.azurewebsites.net
curl -sI "https://sub.target.com/"
# Default Azure 404 or "not found"

# Verify the azurewebsites.net name is unclaimed
curl -sI "https://something.azurewebsites.net/"
```

**Takeover (with authorization only):**
```bash
az webapp create --name something --resource-group RG --plan PLAN
az webapp config hostname add --webapp-name something --resource-group RG --hostname sub.target.com
```

## Phase 5: Wildcard DNS and edge cases

### 5.1 Wildcard detection

```bash
# Test if a wildcard record exists
dig +short A random-nonexistent-123456.target.com

# If it resolves to an IP, a wildcard A record exists
# This can mask dangling CNAMEs on specific subdomains
# To find specific overrides under a wildcard:
# Compare the response for the specific subdomain vs the wildcard
dig +short A sub.target.com
dig +short A definitely-not-real-xyz.target.com
# Different IPs or CNAME vs A = sub.target.com has a specific record
```

### 5.2 MX record takeover

```bash
# If MX records point to a claimable service
dig +short MX sub.target.com
# Check if the mail server endpoint is unclaimed
# Impact: receive emails sent to @sub.target.com
```

### 5.3 TXT record and SPF abuse (informational)

```bash
# Check SPF for includes pointing to uncontrolled domains
dig +short TXT target.com | grep spf
# If SPF includes a domain the target doesn't own, an attacker could
# send SPF-authenticated email from target.com
```

### 5.4 CNAME chain depth

```bash
# Some takeovers require following a CNAME chain
dig +trace sub.target.com
# sub.target.com -> intermediary.cdn.com -> final.service.com
# If any link in the chain is dangling, takeover may be possible
```

## Phase 6: Risk and impact assessment

For each confirmed dangling record:

### 6.1 Impact classification

| Takeover type | Impact level | Justification |
|---|---|---|
| NS delegation | Critical | Full DNS control, TLS cert issuance, email interception |
| CNAME to claimable service on `*.target.com` | High | Phishing with trusted domain, cookie theft (parent domain cookies), OAuth redirect abuse |
| CNAME on subdomain with active users | High | Session hijacking via shared cookies, XSS-equivalent via same-origin |
| CNAME on inactive/internal subdomain | Medium | Phishing with trusted domain, brand damage |
| MX record takeover | High | Email interception, password reset hijacking |
| TXT/SPF include on uncontrolled domain | Medium | Authenticated email spoofing |

### 6.2 Cookie scope analysis

```bash
# Check if the parent domain sets cookies that would be sent to the taken-over subdomain
curl -sI "https://target.com/" | grep -i set-cookie
# Cookies set for ".target.com" will be sent to sub.target.com
# This enables session hijacking via subdomain takeover
```

### 6.3 Same-origin implications

If the main application uses `sub.target.com` or `*.target.com` in CORS `Access-Control-Allow-Origin`, a taken-over subdomain can:
- Read authenticated API responses.
- Perform actions as the victim user.
- Bypass CSP if the subdomain is whitelisted.

## Verification requirements

A finding is **confirmed** only when ALL of the following are met:

1. **Dangling record proof**: DNS query output showing the CNAME/NS record pointing to an unclaimed service or NXDOMAIN target.
2. **Service claimability proof**: at least one of:
   - The service returns a "not found" / "no such app" / "NoSuchBucket" response (with specific error text documented).
   - The service endpoint was successfully claimed and a proof page was served (then immediately cleaned up).
   - For NS takeover: the delegated nameserver returns REFUSED/SERVFAIL for the subdomain.
3. **Replayable verification**: the exact dig/curl commands that demonstrate the dangling state.
4. **Impact assessment**: what an attacker can achieve if they claim the subdomain (phishing, cookie theft, email interception, certificate issuance).
5. **Service identification**: the specific third-party service (S3, Heroku, GitHub Pages, etc.) and why it is claimable.

## Output format

```markdown
## Subdomain Takeover Finding: [subdomain]

**Severity**: Critical / High / Medium
**Takeover Type**: CNAME dangling / NS delegation / MX takeover
**Service**: AWS S3 / GitHub Pages / Heroku / Azure / etc.
**Subdomain**: sub.target.com

### DNS evidence
- **Record**: `sub.target.com. CNAME app-old.herokuapp.com.`
- **CNAME target status**: NXDOMAIN / "No such app" response
- **Verification**:
\```bash
dig +short CNAME sub.target.com
# Output: app-old.herokuapp.com.

curl -sI https://sub.target.com/
# HTTP/2 404
# Server: Cowboy
# (Heroku "no such app" error page)
\```

### Claimability proof
- **Method**: Heroku app name `app-old` is available for registration
- **Verification**: `heroku apps:info --app app-old` returns "Couldn't find that app"
- **OR (if takeover was demonstrated)**:
  - Proof page served at `https://sub.target.com/` showing "[YOUR_ID] PoC"
  - Screenshot captured, app immediately destroyed

### Impact
- **Cookie scope**: `.target.com` cookies are sent to `sub.target.com` (session hijacking risk)
- **CORS**: `https://sub.target.com` is in the `Access-Control-Allow-Origin` allowlist
- **Phishing**: trusted domain increases credential harvesting success rate
- **Certificate**: attacker can obtain a valid TLS certificate for `sub.target.com`

### Remediation
- Remove the dangling CNAME record for `sub.target.com` from DNS.
- Audit all CNAME records pointing to third-party services for active use.
- Implement DNS monitoring for record changes and NXDOMAIN responses.
- Review and tighten cookie scope (avoid `.target.com` where possible).
```

## Completion self-check

- [ ] All in-scope root domains have been enumerated for subdomains.
- [ ] CNAME records have been collected and each CNAME target checked for dangling state.
- [ ] NS delegations have been checked for stale/unresponsive nameservers.
- [ ] Each dangling record has been fingerprinted against the service-specific takeover table.
- [ ] HTTP responses from candidate subdomains have been captured and analyzed.
- [ ] Wildcard DNS has been detected and accounted for in the analysis.
- [ ] Cookie scope and CORS implications have been assessed for each finding.
- [ ] Every confirmed finding has DNS evidence, service claimability proof, and impact assessment.
- [ ] Any takeover demonstrations have been immediately cleaned up.
- [ ] All enumeration output and DNS queries are saved as artifacts.
