#!/usr/bin/env python3
"""
idcert - Identify and inspect .crt certificates and .key files
Usage: idcert [--list] [--ca-chain] <file.crt|file.key> [...]
"""

import sys
import os
import re
import shutil
import subprocess
import tempfile


# ---------------------------------------------------------------------------
# Certificate parsing
# ---------------------------------------------------------------------------

def get_cert_info(crt_path: str) -> dict:
    """Retrieve certificate information via openssl."""
    def run(args):
        result = subprocess.run(
            ["openssl", "x509", "-in", crt_path, "-noout"] + args,
            capture_output=True, text=True
        )
        if result.returncode != 0:
            raise ValueError(f"openssl error: {result.stderr.strip()}")
        return result.stdout.strip()

    return {
        "subject": run(["-subject"]),
        "issuer":  run(["-issuer"]),
        "text":    run(["-text"]),
    }


def parse_field(raw: str) -> str:
    """Extract the value after 'subject=' or 'issuer='."""
    if "=" in raw:
        return raw.split("=", 1)[1].strip()
    return raw.strip()


def is_ca(text: str) -> bool:
    """Check whether CA:TRUE is present in Basic Constraints."""
    return "CA:TRUE" in text.upper()


def get_path_len(text: str) -> int | None:
    """Extract the pathlen constraint if present."""
    for line in text.splitlines():
        if "pathlen" in line.lower():
            try:
                return int(line.lower().split("pathlen:")[1].strip())
            except (IndexError, ValueError):
                pass
    return None


def get_san_entries(text: str) -> dict:
    """
    Extract all Subject Alternative Name entries from certificate text.
    Returns a dict with lists per type: DNS, IP, Email, URI.
    """
    san = {"DNS": [], "IP": [], "Email": [], "URI": []}
    in_san = False

    for line in text.splitlines():
        stripped = line.strip()
        if "Subject Alternative Name" in stripped:
            in_san = True
            continue
        if in_san:
            if stripped == "" or (stripped.endswith(":") and not any(k in stripped for k in ["DNS", "IP", "email", "URI"])):
                in_san = False
                continue
            for entry in stripped.split(","):
                entry = entry.strip()
                if entry.upper().startswith("DNS:"):
                    san["DNS"].append(entry.split(":", 1)[1].strip())
                elif entry.upper().startswith("IP ADDRESS:") or entry.upper().startswith("IP:"):
                    san["IP"].append(entry.split(":", 1)[1].strip())
                elif entry.lower().startswith("email:"):
                    san["Email"].append(entry.split(":", 1)[1].strip())
                elif entry.lower().startswith("uri:"):
                    san["URI"].append(entry.split(":", 1)[1].strip())

    return san


# ---------------------------------------------------------------------------
# Key parsing
# ---------------------------------------------------------------------------

def is_encrypted_key(key_path: str) -> bool:
    """Check whether the private key is encrypted (password protected)."""
    try:
        with open(key_path, "r") as f:
            content = f.read()
        return "ENCRYPTED" in content.upper() or "Proc-Type" in content
    except Exception:
        return False


def detect_key_type(key_path: str) -> tuple[str, dict]:
    """
    Detect the key type and extract details.
    Returns (key_type_label, details_dict).
    """
    def run(cmd):
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode, result.stdout.strip(), result.stderr.strip()

    # Try RSA
    rc, out, _ = run(["openssl", "rsa", "-in", key_path, "-noout", "-text"])
    if rc == 0:
        bits = None
        for line in out.splitlines():
            if "Private-Key" in line:
                match = re.search(r'\((\d+)\s*bit', line)
                if match:
                    bits = int(match.group(1))
                    break
        return "🔑 RSA PRIVATE KEY", {"Bits": bits}

    # Try EC
    rc, out, _ = run(["openssl", "ec", "-in", key_path, "-noout", "-text"])
    if rc == 0:
        curve, nist = None, None
        for line in out.splitlines():
            if "ASN1 OID:" in line:
                curve = line.split(":", 1)[1].strip()
            if "NIST CURVE:" in line:
                nist = line.split(":", 1)[1].strip()
        details = {"Curve": curve}
        if nist:
            details["NIST"] = nist
        return "🔑 EC (ELLIPTIC CURVE) PRIVATE KEY", details

    # Try DSA
    rc, out, _ = run(["openssl", "dsa", "-in", key_path, "-noout", "-text"])
    if rc == 0:
        bits = None
        for line in out.splitlines():
            if "Private-Key" in line:
                match = re.search(r'\((\d+)\s*bit', line)
                if match:
                    bits = int(match.group(1))
                    break
        return "🔑 DSA PRIVATE KEY", {"Bits": bits}

    # Try generic pkey (Ed25519, Ed448, X25519, etc.)
    rc, out, _ = run(["openssl", "pkey", "-in", key_path, "-noout", "-text"])
    if rc == 0:
        key_label = "🔑 PRIVATE KEY (unknown type)"
        for line in out.splitlines():
            low = line.lower()
            if "ed25519" in low:
                key_label = "🔑 Ed25519 PRIVATE KEY"
            elif "ed448" in low:
                key_label = "🔑 Ed448 PRIVATE KEY"
            elif "x25519" in low:
                key_label = "🔑 X25519 PRIVATE KEY"
        return key_label, {}

    # Try public key
    rc, _, _ = run(["openssl", "pkey", "-in", key_path, "-noout", "-pubin"])
    if rc == 0:
        return "🔓 PUBLIC KEY", {}

    return "❓ UNKNOWN KEY TYPE", {}


# ---------------------------------------------------------------------------
# Data collection (returns dicts, no printing)
# ---------------------------------------------------------------------------

def collect_key_data(key_path: str) -> dict:
    """Collect key information as a dict."""
    if not os.path.isfile(key_path):
        return {"file": key_path, "error": "File not found"}

    encrypted = is_encrypted_key(key_path)
    key_type, details = detect_key_type(key_path)

    return {
        "file":      os.path.basename(key_path),
        "kind":      "Key",
        "type":      key_type,
        "details":   ", ".join(f"{k}: {v}" for k, v in details.items() if v is not None),
        "encrypted": "🔒 Yes" if encrypted else "🔓 No",
        "san_dns":   "-",
        "san_ip":    "-",
        "warning":   "" if encrypted else "⚠️  Key is not encrypted",
    }


def collect_cert_data(crt_path: str) -> dict:
    """Collect certificate information as a dict."""
    try:
        info = get_cert_info(crt_path)
    except ValueError as e:
        return {"file": crt_path, "error": str(e)}

    subject        = parse_field(info["subject"])
    issuer         = parse_field(info["issuer"])
    ca             = is_ca(info["text"])
    san            = get_san_entries(info["text"])
    is_self_signed = (subject == issuer)

    if ca and is_self_signed:
        cert_type = "🔐 Root CA"
    elif ca and not is_self_signed:
        cert_type = "🔗 Intermediate CA"
    elif not ca and is_self_signed:
        cert_type = "⚠️  Self-signed"
    else:
        cert_type = "📋 End-entity"

    return {
        "file":      os.path.basename(crt_path),
        "kind":      "Certificate",
        "type":      cert_type,
        "subject":   subject,
        "issuer":    issuer,
        "san_dns":   ", ".join(san["DNS"])   if san["DNS"]   else "-",
        "san_ip":    ", ".join(san["IP"])    if san["IP"]    else "-",
        "san_email": ", ".join(san["Email"]) if san["Email"] else "-",
        "san_uri":   ", ".join(san["URI"])   if san["URI"]   else "-",
        "warning":   "" if any(san.values()) else "⚠️  No SAN entries",
    }


# ---------------------------------------------------------------------------
# Detail output (verbose, one file at a time)
# ---------------------------------------------------------------------------

def print_key_detail(data: dict) -> None:
    if "error" in data:
        print(f"\n❌ {data['file']}: {data['error']}")
        return

    print(f"\n🗝️  Key file: {data['file']}\n{'─' * 50}")
    print(f"  Type        : {data['type']}")
    if data["details"]:
        print(f"  Details     : {data['details']}")
    print(f"  Encrypted   : {data['encrypted']}")
    if data["warning"]:
        print(f"\n  {data['warning']}")
        print("  Consider encrypting: openssl rsa -aes256 -in key.key -out key_enc.key")
    print()
    print("─" * 50)


def print_cert_detail(data: dict) -> None:
    if "error" in data:
        print(f"\n❌ {data.get('file', '?')}: {data['error']}")
        return

    print(f"  Type    : {data['type']}")
    print(f"  Subject : {data.get('subject', '-')}")
    print(f"  Issuer  : {data.get('issuer', '-')}")
    print()

    has_san = any(data.get(k, "-") != "-" for k in ["san_dns", "san_ip", "san_email", "san_uri"])
    if has_san:
        print("  SAN entries:")
        if data.get("san_dns", "-") != "-":
            for e in data["san_dns"].split(", "):
                print(f"    🌐 DNS   : {e}")
        if data.get("san_ip", "-") != "-":
            for e in data["san_ip"].split(", "):
                print(f"    🖥️  IP    : {e}")
        if data.get("san_email", "-") != "-":
            for e in data["san_email"].split(", "):
                print(f"    📧 Email : {e}")
        if data.get("san_uri", "-") != "-":
            for e in data["san_uri"].split(", "):
                print(f"    🔗 URI   : {e}")
    else:
        print("  SAN entries : ⚠️  None found")
    print()
    print("─" * 50)


# ---------------------------------------------------------------------------
# Table output (--list mode)
# ---------------------------------------------------------------------------

def print_table(rows: list[dict]) -> None:
    """Render a list of dicts as an ASCII table, scaled to terminal width."""

    # Columns: (header, key, min_width, priority — higher = shrink first)
    columns = [
        ("File",      "file",      20, 1),
        ("Kind",      "kind",      13, 5),
        ("Type",      "type",      18, 4),
        ("Subject",   "subject",   25, 2),
        ("SAN DNS",   "san_dns",   20, 3),
        ("SAN IP",    "san_ip",    15, 6),
        ("Encrypted", "encrypted", 12, 7),
        ("Order",     "order",      7, 8),
        ("Warning",   "warning",   20, 3),
    ]

    # Normalise rows to uniform keys
    normalized = []
    for r in rows:
        if "error" in r:
            normalized.append({
                "file":      r.get("file", "?"),
                "kind":      "❌ Error",
                "type":      r["error"],
                "subject":   "-",
                "san_dns":   "-",
                "san_ip":    "-",
                "encrypted": "-",
                "order":     "-",
                "warning":   "",
            })
        elif r.get("kind") == "Key":
            normalized.append({
                "file":      r["file"],
                "kind":      "Key",
                "type":      r.get("type", ""),
                "subject":   r.get("details", ""),
                "san_dns":   "-",
                "san_ip":    "-",
                "encrypted": r.get("encrypted", ""),
                "order":     "-",
                "warning":   r.get("warning", ""),
            })
        else:
            remarks = []
            if r.get("order_note"):
                remarks.append(r["order_note"])
            if r.get("warning"):
                remarks.append(r["warning"])
            normalized.append({
                "file":      r.get("file", "?"),
                "kind":      r.get("kind", ""),
                "type":      r.get("type", ""),
                "subject":   r.get("subject", "-"),
                "san_dns":   r.get("san_dns", "-"),
                "san_ip":    r.get("san_ip",  "-"),
                "encrypted": "-",
                "order":     r.get("order_status", "-"),
                "warning":   " | ".join(remarks) if remarks else "",
            })

    # Calculate column widths from content
    def content_width(key: str, header: str) -> int:
        w = len(header)
        for row in normalized:
            w = max(w, len(str(row.get(key, ""))))
        return w

    widths = {key: content_width(key, header) for header, key, *_ in columns}

    # Scale to terminal width — shrink higher-priority columns first
    term_width = shutil.get_terminal_size(fallback=(120, 24)).columns - 2

    def table_width(w: dict) -> int:
        return sum(v + 3 for v in w.values()) + 1

    if table_width(widths) > term_width:
        for header, key, min_w, _ in sorted(columns, key=lambda c: -c[3]):
            if table_width(widths) <= term_width:
                break
            reduction = min(table_width(widths) - term_width, widths[key] - min_w)
            widths[key] -= reduction

    def truncate(val: str, width: int) -> str:
        return val.ljust(width) if len(val) <= width else val[:width - 1] + "…"

    def row_str(row: dict) -> str:
        return "| " + " | ".join(truncate(str(row.get(key, "")), widths[key]) for _, key, *_ in columns) + " |"

    def separator() -> str:
        return "+" + "+".join("-" * (widths[key] + 2) for _, key, *_ in columns) + "+"

    header_row = {key: header for header, key, *_ in columns}
    print()
    print(separator())
    print(row_str(header_row))
    print(separator())
    for row in normalized:
        print(row_str(row))
    print(separator())
    print(f"\n  Total: {len(normalized)} file(s)\n")


# ---------------------------------------------------------------------------
# Chain handling
# ---------------------------------------------------------------------------

def split_pem_blocks(path: str) -> list[str]:
    """Split a PEM file into individual certificate blocks."""
    with open(path, "r") as f:
        content = f.read()
    return re.findall(
        r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
        content, re.DOTALL
    )


def is_chain_file(path: str) -> bool:
    """Return True if the file contains more than one certificate block."""
    try:
        return len(split_pem_blocks(path)) > 1
    except Exception:
        return False


def validate_chain_order(certs: list[dict], ca_chain: bool = False) -> list[dict]:
    """
    Validate the order of certificates in a chain.

    Normal chain  (ca_chain=False): end-entity → intermediate(s) → root CA
    CA-chain      (ca_chain=True):  intermediate(s) → root CA  (no end-entity expected)

    Checks:
      - Each cert's issuer must match the subject of the next cert
      - Normal chain: first cert must be an end-entity
      - CA-chain:     first cert must be an Intermediate CA
      - Last cert must be a Root CA
      - Middle certs must be Intermediate CAs
    """
    n = len(certs)
    errors = []

    for cert in certs:
        cert["order_status"] = "✅"
        cert["order_note"]   = ""

    # Check issuer → subject linkage
    for i in range(n - 1):
        issuer_current = certs[i].get("issuer", "")
        subject_next   = certs[i + 1].get("subject", "")
        if issuer_current and subject_next and issuer_current != subject_next:
            errors.append(
                f"#{i+1} issuer does not match #{i+2} subject\n"
                f"         Issuer  #{i+1}: {issuer_current}\n"
                f"         Subject #{i+2}: {subject_next}"
            )
            certs[i]["order_status"]   = "❌"
            certs[i]["order_note"]     = f"Issuer ≠ subject of #{i+2}"
            certs[i+1]["order_status"] = "❌"
            certs[i+1]["order_note"]   = f"Subject ≠ issuer of #{i+1}"

    # Check first certificate
    first_type = certs[0].get("type", "")
    if ca_chain:
        if "Intermediate" not in first_type:
            errors.append(f"#1 is not an Intermediate CA ({first_type}), expected with --ca-chain")
            if certs[0]["order_status"] == "✅":
                certs[0]["order_status"] = "⚠️"
                certs[0]["order_note"]   = "Expected Intermediate CA as #1"
    else:
        if "Root" in first_type or "Intermediate" in first_type:
            errors.append(f"#1 is a CA ({first_type}), expected end-entity as first")
            if certs[0]["order_status"] == "✅":
                certs[0]["order_status"] = "⚠️"
                certs[0]["order_note"]   = "Expected end-entity as #1"

    # Check last certificate
    last_type = certs[-1].get("type", "")
    if "Root" not in last_type:
        errors.append(f"#{n} is not a Root CA ({last_type}), expected Root CA as last")
        if certs[-1]["order_status"] == "✅":
            certs[-1]["order_status"] = "⚠️"
            certs[-1]["order_note"]   = "Expected Root CA as last"

    # Check middle certificates
    for i in range(1, n - 1):
        t = certs[i].get("type", "")
        if "Intermediate" not in t:
            errors.append(f"#{i+1} is not an Intermediate CA ({t})")
            if certs[i]["order_status"] == "✅":
                certs[i]["order_status"] = "⚠️"
                certs[i]["order_note"]   = "Expected Intermediate CA"

    certs[0]["chain_valid"]  = len(errors) == 0
    certs[0]["chain_errors"] = errors
    certs[0]["chain_mode"]   = "CA-chain" if ca_chain else "Normal chain"

    return certs


def collect_chain_data(path: str, ca_chain: bool = False) -> list[dict]:
    """
    Process a chain file: analyse each certificate block separately
    and validate the order.
    """
    blocks   = split_pem_blocks(path)
    results  = []
    basename = os.path.basename(path)

    for i, block in enumerate(blocks, start=1):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".crt", delete=False) as tmp:
            tmp.write(block)
            tmp_path = tmp.name
        try:
            data = collect_cert_data(tmp_path)
            data["file"] = f"{basename} [#{i}/{len(blocks)}]"
            data["kind"] = f"Chain ({i}/{len(blocks)})"
            results.append(data)
        finally:
            os.unlink(tmp_path)

    return validate_chain_order(results, ca_chain=ca_chain)


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

def process_path(path: str, ca_chain: bool = False) -> list[dict]:
    """
    Determine file type and collect data.
    Always returns a list (chain files produce multiple dicts).
    """
    ext = os.path.splitext(path)[1].lower()

    if ext == ".key":
        return [collect_key_data(path)]

    if ext in (".crt", ".pem", ".cer") or ext == "":
        try:
            if is_chain_file(path):
                return collect_chain_data(path, ca_chain=ca_chain)
        except Exception:
            pass
        return [collect_cert_data(path)]

    try:
        with open(path, "r") as f:
            first_line = f.readline().strip()
        if "PRIVATE KEY" in first_line or "PUBLIC KEY" in first_line:
            return [collect_key_data(path)]
        elif "CERTIFICATE" in first_line:
            if is_chain_file(path):
                return collect_chain_data(path, ca_chain=ca_chain)
            return [collect_cert_data(path)]
    except Exception:
        pass

    return [{"file": path, "error": "Unknown file type"}]


def print_detail(data: dict) -> None:
    kind = data.get("kind", "")
    if kind == "Key":
        print_key_detail(data)
    elif kind.startswith("Chain"):
        print(f"\n{'═' * 55}")
        print(f"  🔗 Chain certificate: {data['file']}  {data.get('order_status', '')}")
        if data.get("order_note"):
            print(f"  ↳ {data['order_note']}")
        print(f"{'═' * 55}")
        print_cert_detail(data)

        if "chain_valid" in data:
            mode = data.get("chain_mode", "")
            print(f"  Mode  : {mode}")
            print()
            if data["chain_valid"]:
                print(f"  ✅ Chain order is CORRECT ({mode})")
            else:
                print(f"  ❌ Chain order has ERRORS ({mode}):")
                for err in data["chain_errors"]:
                    print(f"     • {err}")
            print()
    else:
        print(f"\n📄 Certificate: {data.get('file', '?')}\n{'─' * 50}")
        print_cert_detail(data)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: idcert [--list] [--ca-chain] <file> [...]")
        print()
        print("  --list      Table output instead of per-file detail")
        print("  --ca-chain  Chain has no end-entity (intermediate + root only)")
        print()
        print("Examples:")
        print("  idcert server.crt")
        print("  idcert --list *.crt *.key")
        print("  idcert chain.crt")
        print("  idcert --ca-chain ca-chain.crt")
        print("  idcert --list --ca-chain ca-chain.crt")
        sys.exit(1)

    args      = sys.argv[1:]
    list_mode = "--list"     in args
    ca_chain  = "--ca-chain" in args
    files     = [a for a in args if not a.startswith("--")]

    if not files:
        print("❌ No files specified.")
        sys.exit(1)

    results = []
    for path in files:
        results.extend(process_path(path, ca_chain=ca_chain))

    if list_mode:
        print_table(results)
    else:
        for data in results:
            print_detail(data)


if __name__ == "__main__":
    main()
