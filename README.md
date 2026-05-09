# idcert

## Features

- 🔐 Classifies certificates as **Root CA**, **Intermediate CA**, **Self-signed**, or **End-entity**
- 🔑 Detects key type (**RSA**, **EC**, **DSA**, **Ed25519**, **Ed448**, **X25519**) and key size
- 🔒 Warns when a private key is **not encrypted**
- 🌐 Extracts **SAN entries** (DNS, IP, Email, URI)
- 🔗 Automatically detects and splits **chain files** (multiple PEM blocks in one file)
- ✅ Validates **chain order** and issuer/subject linkage
- 📋 **Table output** (`--list`) with auto-resize to terminal width
- 🔧 **Bash completion** included

---

## Requirements

- Python 3.10+
- `openssl` (available on Linux/macOS by default; on Windows via Git Bash or [OpenSSL for Windows](https://slproweb.com/products/Win32OpenSSL.html))

---

## Installation

```bash
# Download the script
curl -O https://raw.githubusercontent.com/your-username/idcert/main/idcert

# Make it executable
chmod +x idcert

# Move to a directory in your PATH
sudo mv idcert /usr/local/bin/idcert
```

**Or for your user only (no sudo):**

```bash
mkdir -p ~/.local/bin
mv idcert ~/.local/bin/idcert
chmod +x ~/.local/bin/idcert

# Add to PATH if not already present (add to ~/.bashrc or ~/.zshrc)
export PATH="$HOME/.local/bin:$PATH"
```

### Bash completion

```bash
# System-wide
sudo cp idcert_completion.bash /etc/bash_completion.d/idcert

# Or for your user only
mkdir -p ~/.bash_completion.d
cp idcert_completion.bash ~/.bash_completion.d/idcert
echo 'source ~/.bash_completion.d/idcert' >> ~/.bashrc
source ~/.bashrc
```

---

## Usage

```
idcert [--list] [--ca-chain] <file> [...]

  --list      Table output instead of per-file detail
  --ca-chain  Chain has no end-entity (intermediate + root only)
```

### Examples

```bash
# Inspect a single certificate
idcert server.crt

# Inspect a private key
idcert server.key

# Inspect multiple files at once
idcert *.crt *.key

# Table output
idcert --list *.crt *.key

# Inspect a chain file (auto-detected)
idcert chain.crt

# Validate a CA-only chain (no end-entity expected)
idcert --ca-chain ca-chain.crt

# Combine flags
idcert --list --ca-chain ca-chain.crt
```

---

## Output

### Detail mode (default)

```
📄 Certificate: server.crt
──────────────────────────────────────────────────
  Type    : 📋 End-entity
  Subject : CN=webserver.example.com
  Issuer  : CN=My Intermediate CA

  SAN entries:
    🌐 DNS   : webserver.example.com
    🌐 DNS   : www.example.com
    🖥️  IP    : 192.168.1.10
──────────────────────────────────────────────────

🗝️  Key file: server.key
──────────────────────────────────────────────────
  Type        : 🔑 RSA PRIVATE KEY
  Details     : Bits: 2048
  Encrypted   : 🔓 No

  ⚠️  Key is not encrypted
  Consider encrypting: openssl rsa -aes256 -in key.key -out key_enc.key
──────────────────────────────────────────────────
```

### Chain file

```
═══════════════════════════════════════════════════════
  🔗 Chain certificate: chain.crt [#1/3]  ✅
═══════════════════════════════════════════════════════
  Type    : 📋 End-entity
  ...

  Mode  : Normal chain

  ✅ Chain order is CORRECT (Normal chain)
```

### Table mode (`--list`)

```
+----------------------+-------------+--------------------+---------------------------+----------------------+-----------------+--------------+-------+----------------------+
| File                 | Kind        | Type               | Subject                   | SAN DNS              | SAN IP          | Encrypted    | Order | Warning              |
+----------------------+-------------+--------------------+---------------------------+----------------------+-----------------+--------------+-------+----------------------+
| root_ca.crt          | Certificate | 🔐 Root CA         | CN=My Root CA             | -                    | -               | -            | -     |                      |
| intermediate_ca.crt  | Certificate | 🔗 Intermediate CA | CN=My Intermediate CA     | -                    | -               | -            | -     |                      |
| server.crt           | Certificate | 📋 End-entity      | CN=webserver.example.com  | webserver.example.com| 192.168.1.10    | -            | -     |                      |
| server.key           | Key         | 🔑 RSA PRIVATE KEY | Bits: 2048                | -                    | -               | 🔓 No        | -     | ⚠️  Key not encrypted |
+----------------------+-------------+--------------------+---------------------------+----------------------+-----------------+--------------+-------+----------------------+

  Total: 4 file(s)
```

---

## Certificate types

| Icon | Type | CA:TRUE | Self-signed |
|---|---|---|---|
| 🔐 | Root CA | ✅ | ✅ |
| 🔗 | Intermediate CA | ✅ | ❌ |
| ⚠️ | Self-signed (no CA) | ❌ | ✅ |
| 📋 | End-entity (leaf) | ❌ | ❌ |

## Key types

| Icon | Type | Details shown |
|---|---|---|
| 🔑 | RSA | Key size in bits |
| 🔑 | EC | Curve name + NIST name |
| 🔑 | DSA | Key size in bits |
| 🔑 | Ed25519 / Ed448 / X25519 | Modern key types |
| 🔓 | Public key | Detected separately |

---

## Chain validation

`idcert` automatically detects files containing multiple PEM blocks and validates the chain order.

**Normal chain** (`end-entity → intermediate(s) → root CA`):
```bash
cat server.crt intermediate.crt root.crt > chain.crt
idcert chain.crt
```

**CA-only chain** (`intermediate → root CA`, no end-entity):
```bash
cat intermediate.crt root.crt > ca-chain.crt
idcert --ca-chain ca-chain.crt
```

Validation checks:
- Issuer of each certificate matches the Subject of the next
- First certificate is an end-entity (or Intermediate CA with `--ca-chain`)
- Middle certificates are Intermediate CAs
- Last certificate is a Root CA

---

## Building a chain

```bash
# Full chain (end-entity + intermediate + root)
cat server.crt intermediate.crt root.crt > chain.crt

# Without root (common for web servers — root is in the OS trust store)
cat server.crt intermediate.crt > chain.crt
```

---

## Files

| File | Description |
|---|---|
| `idcert` | Main script (no `.py` extension, ready for PATH) |
| `idcert.py` | Same script with `.py` extension |
| `idcert_completion.bash` | Bash tab-completion |

---

## License

MIT
