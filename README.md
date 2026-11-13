# Protolan

Protolan is a lightweight network exposure scanner written in Go. It ships as
one static binary, needs no root privileges, and has no runtime dependencies.

It is early. Version 0.1 finds responsive hosts and open TCP ports and writes
a stable JSON report. Device identification, drift detection and policy
checks are planned and are listed under [Roadmap](#roadmap); they do not
exist yet.

> Only scan networks you own or are authorized in writing to test.
> Unauthorized scanning may be illegal where you live.

## What 0.1 does

- TCP connect scanning of IPv4 and IPv6 addresses, CIDR prefixes and ranges
- Runs as an ordinary user: no raw sockets, no packet-capture driver
- Refuses public addresses unless you pass `--allow-public`
- Caps the number of hosts per run (`--max-hosts`, default 4096)
- Global rate limit and concurrency limit
- `--dry-run` to see the plan before anything is sent
- Text or versioned JSON output
- Optional audit log: one JSON line when a scan starts and one when it ends.
  If the log cannot be written, the scan does not run.

## What it does not do

- No SYN, UDP or OS fingerprinting. Those need raw packets and root.
- No service or device identification yet.
- No hostname targets. Give it addresses, so scope checks are unambiguous.
- A host that silently drops every probe looks the same as an absent host
  and is reported as not up.

Protolan does not use, wrap or bundle Nmap or its data files.

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

# Slow and gentle, with an audit trail
protolan scan -rate 50 -audit-log ~/protolan-audit.jsonl 192.168.1.0/24
```

| Flag | Default | Meaning |
|---|---|---|
| `-p`, `-ports` | `common` | `common` (58 ports), `all`, or a list such as `22,80,8000-8100` |
| `-timeout` | `1.5s` | Per-connection timeout |
| `-rate` | `500` | New connections per second, `0` for unlimited |
| `-concurrency` | `128` | Simultaneous connection attempts |
| `-max-hosts` | `4096` | Refuse to expand targets beyond this |
| `-allow-public` | off | Permit non-private addresses |
| `-format` | `text` | `text` or `json` |
| `-o`, `-output` | stdout | Report file, created with mode 0600 |
| `-all-states` | off | Also list closed and filtered ports on responsive hosts |
| `-dry-run` | off | Validate and print the plan only |
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
  "tool": { "name": "protolan", "version": "0.1.0" },
  "started_at": "2026-11-13T00:10:00Z",
  "finished_at": "2026-11-13T00:10:29Z",
  "parameters": {
    "targets": ["192.168.1.0/24"],
    "ports": "common",
    "method": "tcp-connect",
    "timeout_ms": 1500,
    "concurrency": 128,
    "rate_per_sec": 500,
    "allow_public": false
  },
  "summary": {
    "hosts_scanned": 254,
    "hosts_up": 1,
    "open_ports": 2,
    "probes_planned": 14732,
    "probes_sent": 14732,
    "probe_errors": 0,
    "interrupted": false
  },
  "hosts": [
    {
      "address": "192.168.1.1",
      "ports": [
        { "port": 53, "protocol": "tcp", "state": "open", "latency_ms": 1.2 },
        { "port": 80, "protocol": "tcp", "state": "open", "latency_ms": 1.4 }
      ]
    }
  ]
}
```

## Roadmap

Plans, not promises. Nothing below is implemented.

| Version | Scope |
|---|---|
| 0.2 | Identification: service banners, mDNS and SSDP discovery, vendor lookup, and rule-based device typing that shows the evidence for each verdict. Rules as small YAML files with test fixtures. |
| 0.3 | Inventory and drift: store scans locally and report new hosts, vanished hosts and newly opened ports. |
| 0.4 | Policy as code: declare what each segment may expose and fail when reality differs. Exceptions with an owner, a reason and an expiry date. TLS certificate inventory. |
| 0.5 | Reconciliation against a declared inventory, to surface undeclared devices. |
| Later | API, scheduling, multiple sensors, signed releases with an SBOM. |

## Development

```sh
go test -race ./...
go vet ./...
golangci-lint run ./...
```

The engine tests run against loopback listeners and a fake dialer, so they
send nothing off the machine.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## License

Apache License 2.0. See [LICENSE](LICENSE).
