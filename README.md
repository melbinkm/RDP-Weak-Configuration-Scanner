# RDP Weak Configuration Scanner

A minimal, single-file Python script designed to audit Remote Desktop Protocol (RDP) configurations. It performs both unauthenticated network probing and authenticated registry inspections to determine the security posture of RDP listeners.

> ⚠️ Only use this tool on systems and networks you own or have explicit permission to test.

---

## Features

### 1. Unauthenticated Network Probe

Knocks on the RDP port to determine:

- **NLA Support**  
  Detects if Network Level Authentication is **required**, **optional**, or **missing**.

- **TLS Versions**  
  Enumerates supported protocols:
  - TLS 1.0  
  - TLS 1.1  
  - TLS 1.2  
  - TLS 1.3  

- **Certificate Analysis**  
  Extracts and fingerprints the RDP SSL certificate:
  - SHA-1 thumbprint per successful TLS handshake.

- **CredSSP**  
  Verifies if Credential Security Support Provider is supported.

---

### 2. Authenticated Posture Linter (Optional)

Uses Impacket to connect via SMB and Remote Registry to read the **ground truth** configuration:

- **RDP Status**  
  Checks if `fDenyTSConnections` is set (is RDP actually enabled?).

- **Shadowing / Remote Assistance**  
  Checks `fAllowToGetHelp`.

- **True NLA Enforcement**  
  Verifies the `UserAuthentication` registry key (e.g. `UserAuthentication=1`).

- **Redirection Policies**  
  Checks if clipboard or drive redirection is blocked via listener settings or Group Policy:
  - `fDisableClip`
  - `fDisableCdm`
  - `DisableClipboardRedirection`
  - `DisableDriveRedirection`

- **Port Verification**  
  Compares the registry’s configured `PortNumber` against the port you scanned to detect forwarding/mismatches.

---

## Requirements

### Python

- **Version:** 3.8+

### Dependencies

- **Standard Library:**
  - `socket`, `ssl`, `struct`, `json`, `argparse`, `hashlib`, etc.
- **Optional (for `--auth`):**
  - [`impacket`](https://github.com/SecureAuthCorp/impacket)

---

## Installation

Download the script:

```bash
wget https://raw.githubusercontent.com/your-repo/rdp_weak_scan.py
chmod +x rdp_weak_scan.py
````

Install Impacket (recommended for auth checks):

```bash
pip install impacket
```

The script runs without Impacket, but `--auth`-related features will be disabled.

---

## Usage

```bash
python3 rdp_weak_scan.py [targets] [options]
```

---

## Target Specification

Targets can be hostnames, IPv4 addresses, or IPv6 addresses.

Examples:

* `192.168.1.10`
  → Default port **3389**

* `192.168.1.10:3390`
  → Custom port **3390**

* `[2001:db8::1]`
  → IPv6, default port **3389**

* `[2001:db8::1]:3390`
  → IPv6, custom port **3390**

---

## Authentication Options

> 💡 Avoid passing passwords directly on the command line in shared environments.

### Environment Variable (Best Practice)

```bash
export RDP_SCAN_AUTH="DOMAIN\User:Password"
python3 rdp_weak_scan.py 10.0.0.5 --auth-env
```

### File Input

```bash
# Create a file with one line: DOMAIN\User:Password
python3 rdp_weak_scan.py 10.0.0.5 --auth-file creds.txt
```

### CLI Flag (Not Recommended)

```bash
python3 rdp_weak_scan.py 10.0.0.5 --auth "CORP\Admin:Secret123"
```

---

## Other Options

| Flag                    | Description                                                                                   |
| ----------------------- | --------------------------------------------------------------------------------------------- |
| `--targets-file FILE`   | Read a list of targets from a file (one per line).                                            |
| `--json`                | Output results in JSON format (useful for parsing/automation).                                |
| `--strict-tls`          | Return exit code `2` if weak TLS (1.0/1.1) is detected (CI/CD friendly).                      |
| `--expected-thumbprint` | Warn if the server’s certificate thumbprint does not match this SHA-1 value (MITM detection). |
| `--timeout SEC`         | Set connection timeout (default: `3.0` seconds).                                              |
| `--delay SEC`           | Rate limiting delay between targets (default: `0.0` seconds).                                 |
| `-v`, `--verbose`       | Enable verbose error logging.                                                                 |


---

## Examples

### 1. Quick Network Scan (Unauthenticated)

Check if a server supports weak TLS 1.0 without logging in:

```bash
python3 rdp_weak_scan.py 192.168.1.50
```

---

### 2. Full Security Audit (Authenticated)

Check if clipboard redirection is disabled via Registry/GPO:

```bash
export RDP_SCAN_AUTH="CORP\Auditor:P@ssword!"
python3 rdp_weak_scan.py 192.168.1.50 --auth-env --json
```

---

### 3. CI/CD Policy Check

Fail the build if any server in `targets.txt` supports TLS 1.0:

```bash
python3 rdp_weak_scan.py --targets-file targets.txt --strict-tls
if [ $? -eq 2 ]; then
    echo "Policy Violation: Weak TLS detected!"
    exit 1
fi
```

---

### 4. Certificate Pinning

Ensure the jump host is presenting the expected certificate:

```bash
python3 rdp_weak_scan.py jumpbox.corp.local \
    --expected-thumbprint "a1b2c3d4e5..."
```

---

## Exit Codes

| Code | Meaning                                                   |
| ---- | --------------------------------------------------------- |
| 0    | Scan completed successfully.                              |
| 1    | Argument or input error.                                  |
| 2    | Strict TLS check failed (only if `--strict-tls` is used). |

---

## Security Considerations

* **Credentials**
  When using authenticated mode, the script authenticates via SMB. Use an account with the **minimal necessary permissions** (Remote Registry access).

* **Active Scanning**
  This tool interacts with the network stack and creates TCP connections. It may trigger IDS/IPS signatures for **RDP scanning / enumeration**.

---

## License

Open source.
Use responsibly and **only** on systems and networks you own or have explicit permission to audit.
