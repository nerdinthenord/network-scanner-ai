# Protolan

Protolan is a lightweight network exposure scanner written in Go. It ships as
one static binary, needs no root privileges, and has no runtime dependencies.

It is early. Version 0.2 finds responsive hosts and open TCP ports, works out
what service is on each port, and gives a device verdict with the evidence
behind it. Drift detection and policy checks are planned and are listed under
[Roadmap](#roadmap); they do not exist yet.

> Only scan networks you own or are authorized in writing to test.
> Unauthorized scanning may be illegal where you live.

## What it does

**Scanning**
- TCP connect scanning of IPv4 and IPv6 addresses, CIDR prefixes and ranges
- Runs as an ordinary user: no raw sockets, no packet-capture driver
- Global rate limit and concurrency limit

**Identification**
- Reads service banners (SSH, FTP, SMTP, POP3, IMAP, VNC)
- Fetches the HTTP status, `Server` header and page title
- Records the TLS version and certificate subject, issuer, validity dates
  and fingerprint, including for self-signed and expired certificates
- Applies declarative rules to name the device, and prints the evidence
  for every verdict so you can judge it yourself

**Safeguards**
- Refuses public addresses unless you pass `--allow-public`
- Caps the number of hosts per run (`--max-hosts`, default 4096)
- `--dry-run` shows the plan before anything is sent
- Never sends data to raw-print ports (515, 9100-9107), which would
  otherwise print it
- Optional audit log: one JSON line when a scan starts and one when it ends.
  If the log cannot be written, the scan does not run.

## What it does not do

- No SYN, UDP or OS fingerprinting. Those need raw packets and root.
- No mDNS, SSDP or MAC-vendor lookup yet, so identification relies on
  ports, banners, HTTP and TLS only.
- No hostname targets. Give it addresses, so scope checks are unambiguous.
- A host that silently drops every probe looks the same as an absent host
  and is reported as not up.

Protolan does not use, wrap or bundle Nmap or its data files.

## How identification works, and its limits

After the port scan, Protolan connects to each open port and listens. If the
service says nothing, it sends one plain `GET /` request, and if that fails
it tries a TLS handshake. That is at most three extra connections per open
port. Use `-no-identify` to skip this step entirely.

Rules then turn those facts into a verdict. Each rule has a confidence level:

| Confidence | Typical basis |
|---|---|
| `high` | A banner or page title that names the product |
| `medium` | A distinctive combination of open ports, or a title that can be customised |
| `low` | A single open port |

The built-in rules are a starter set of 25, written from well-known port and
banner conventions. **They have not been validated against a labelled set of
real devices, and no accuracy figure exists yet.** Treat `low` verdicts as
hints. List the rules with `protolan rules`.

### Writing rules

Rules are JSON. A rule matches when every `all` condition holds and, if `any`
is present, at least one of those holds. Each condition must be satisfied by
a single open port.

```json
[
  {
    "id": "lab-nas",
    "device": {"type": "nas", "vendor": "Example", "product": "Example NAS"},
    "confidence": "high",
    "all": [{"http_title_contains": "Example NAS"}],
    "example": [
      {"port": 80, "service": {"http": {"status": 200, "title": "Example NAS login"}}}
    ]
  }
]
```

Condition fields: `port`, `service`, `banner_contains`,
`http_server_contains`, `http_title_contains`, `tls_subject_contains`,
`tls_issuer_contains`. A condition with only `port` means "this port is
open". Text matching ignores case. Every rule needs an `example` it matches.

Load your own rules alongside the built-in ones with `-rules file.json`.

## Install

Requires Go 1.24 or newer.

```sh
git clone https://github.com/nerdinthenord/protolan.git
cd protolan
CGO_ENABLED=0 go build -trimpath -o protolan ./cmd/protolan
```

There are no tagged releases or prebuilt binaries yet.

## Usage

Flags come before targets.

```sh
# Common ports on a home or office subnet
protolan scan 192.168.1.0/24

# Specific ports, JSON to a file
protolan scan -p 22,80,443,8000-8100 -format json -o scan.json 10.0.0.0/24

# See what would happen without sending anything
protolan scan -dry-run -p all 192.168.1.10-192.168.1.20

# Port scan only, no service probing
protolan scan -no-identify 192.168.1.0/24

# Slow and gentle, with an audit trail
protolan scan -rate 50 -audit-log ~/protolan-audit.jsonl 192.168.1.0/24
```

| Flag | Default | Meaning |
|---|---|---|
| `-p`, `-ports` | `common` | `common` (62 ports), `all`, or a list such as `22,80,8000-8100` |
| `-timeout` | `1.5s` | Per-connection timeout |
| `-rate` | `500` | New connections per second, `0` for unlimited |
| `-concurrency` | `128` | Simultaneous connection attempts |
| `-max-hosts` | `4096` | Refuse to expand targets beyond this |
| `-allow-public` | off | Permit non-private addresses |
| `-format` | `text` | `text` or `json` |
| `-o`, `-output` | stdout | Report file, created with mode 0600 |
| `-all-states` | off | Also list closed and filtered ports on responsive hosts |
| `-dry-run` | off | Validate and print the plan only |
| `-no-identify` | off | Skip service probing and device identification |
| `-rules` | none | JSON file of additional identification rules |
| `-audit-log` | off | Audit file, also settable with `PROTOLAN_AUDIT_LOG` |

### Port states

| State | Meaning |
|---|---|
| `open` | The TCP handshake completed |
| `closed` | The host refused the connection |
| `filtered` | No answer in time, or the destination was unreachable |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed |
| 1 | Runtime error, for example an unwritable output file |
| 2 | Usage error, including an out-of-scope target |
| 130 | Interrupted; the partial report is still written |

### JSON output

The JSON document carries `schema_version`. Within a schema version, fields
are added but never renamed or removed.

```json
{
  "schema_version": "1",
  "tool": { "name": "protolan", "version": "0.2.0" },
  "started_at": "2026-11-13T00:10:00Z",
  "finished_at": "2026-11-13T00:10:41Z",
  "parameters": {
    "targets": ["192.168.1.0/24"],
    "ports": "common",
    "method": "tcp-connect",
    "timeout_ms": 1500,
    "concurrency": 128,
    "rate_per_sec": 500,
    "allow_public": false,
    "identify": true
  },
  "summary": {
    "hosts_scanned": 254,
    "hosts_up": 1,
    "open_ports": 2,
    "probes_planned": 15748,
    "probes_sent": 15748,
    "probe_errors": 0,
    "interrupted": false
  },
  "hosts": [
    {
      "address": "192.168.1.20",
      "device": {
        "type": "computer",
        "vendor": "Canonical",
        "product": "Ubuntu Linux host",
        "confidence": "high",
        "rule": "ssh-ubuntu",
        "evidence": [
          "port 22/tcp speaks ssh; banner contains \"Ubuntu\" (\"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\")"
        ]
      },
      "ports": [
        {
          "port": 22, "protocol": "tcp", "state": "open", "latency_ms": 1.2,
          "service": { "name": "ssh", "banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5" }
        },
        {
          "port": 443, "protocol": "tcp", "state": "open", "latency_ms": 1.4,
          "service": {
            "name": "https",
            "http": { "status": 200, "server": "nginx", "title": "Welcome" },
            "tls": {
              "version": "TLS 1.3",
              "subject": "host.lan",
              "issuer": "host.lan",
              "not_before": "2026-01-01T00:00:00Z",
              "not_after": "2027-01-01T00:00:00Z",
              "self_signed": true,
              "expired": false,
              "sha256": "<64 hex characters>"
            }
          }
        }
      ]
    }
  ]
}
```

Text that comes from a remote service (banners, headers, titles, certificate
names) is reduced to printable ASCII and capped at 200 characters.

## Roadmap

Plans, not promises. Nothing below is implemented.

| Version | Scope |
|---|---|
| 0.3 | Inventory and drift: store scans locally and report new hosts, vanished hosts and newly opened ports. |
| 0.4 | Policy as code: declare what each segment may expose and fail when reality differs. Exceptions with an owner, a reason and an expiry date. |
| 0.5 | Reconciliation against a declared inventory, to surface undeclared devices. |
| Later | mDNS and SSDP discovery, MAC-vendor lookup, a validated rule set with published accuracy, API, scheduling, multiple sensors, signed releases with an SBOM. |

## Development

```sh
go test -race ./...
go vet ./...
golangci-lint run ./...
```

The tests run against loopback listeners and in-memory connections, so they
send nothing off the machine.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## License

Apache License 2.0. See [LICENSE](LICENSE).
