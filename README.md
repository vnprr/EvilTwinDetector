# WiGuard

WiGuard is a **passive, explainable Evil Twin detector** for Wi-Fi. A monitor-mode
adapter listens to beacons and deauthentication frames; four detectors look for
evidence that an access point is impersonating another one; a correlation step
combines that evidence into one verdict per AP (`info`, `suspicious`,
`evil_twin`) with a plain-language explanation. A read-only API and a React
dashboard show the results.

WiGuard never transmits. It does not associate, inject or deauthenticate, and it
never touches the host's own Wi-Fi interface.

## How detection works

| Detector | What it looks at | Needs enrollment |
|---|---|---|
| **Identity verification** | An enrolled AP whose IE fingerprint, clock skew, RSSI or sequence counter no longer matches its trusted profile; an *unknown* BSSID advertising an enrolled SSID. | yes |
| **Duplicate BSSID** (part of identity) | Two interleaved TSF clocks, or the same BSSID beaconing on two channels at once: two radios behind one MAC address. | no |
| **Environment anomaly** | An AP that differs from the majority of APs sharing its SSID (IE fingerprint, vendor OUIs, IE layout, beacon interval). | no |
| **Deauth storm** | Bursts of deauthentication/disassociation frames, tracked as episodes. | no |

Each signal has a severity (strength 1.0 / 0.6 / 0.3). A module contributes the
strength of its strongest signal times its weight, and the module contributions
are combined with a noisy-OR:

```
score = 1 − Π (1 − weight_m × strength_m)
```

With the default weights one module alone can reach `suspicious` but never
`evil_twin`; two independent modules at full strength reach `evil_twin`. The
score is a heuristic ranking, **not** a calibrated probability. A deauth storm
against the real AP is linked to a twin advertising the same SSID, which is the
classic attack: push clients off the real network, catch them on the copy.

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Install

Python 3.12+ with [uv](https://docs.astral.sh/uv/), and Node 20+ for the dashboard.

```bash
make install        # = uv sync --frozen && (cd dashboard && npm ci)
```

Every dependency is pinned in `uv.lock` and `dashboard/package-lock.json`, so the
environment is reproducible. Commands below use `uv run wiguard …`; inside an
activated virtualenv plain `wiguard …` works too.

## Try it without hardware

Synthetic scenarios (correctly formed 802.11 frames written to pcap files) are
committed under `tests/pcap_fixtures/synthetic`:

```bash
uv run wiguard fixtures evaluate tests/pcap_fixtures/synthetic/manifest.json

# Enroll the "home" network from a known-good capture, then analyse an attack.
uv run wiguard enroll --pcap tests/pcap_fixtures/synthetic/enroll_home.pcap
uv run wiguard analyze tests/pcap_fixtures/synthetic/classic_evil_twin.pcap

# Replay the attack into a state database and look at it in the dashboard.
uv run wiguard replay tests/pcap_fixtures/synthetic/classic_evil_twin.pcap --state-path /tmp/demo.db
uv run wiguard api --state-path /tmp/demo.db
(cd dashboard && npm run dev)        # http://127.0.0.1:5173
```

`wiguard replay` evaluates the capture on the same schedule the live sensor
uses (every `flush_interval_seconds` of capture time), so alert timestamps,
escalations and metric trends look exactly as they would have live.

## Live use

Hardware used so far: Alfa RTL8812AU (`rtw88_8812au` driver) switched directly
to monitor mode; see [docs/hardware/alfa-rtl8812au.md](docs/hardware/alfa-rtl8812au.md).
Set `capture.interface` and `capture.internal_interface` in `config.yaml`.

```bash
# 1. Record trusted profiles of your own APs while the environment is known-good.
sudo .venv/bin/wiguard enroll --duration 120 --ssid MyNetwork

# 2a. A short scan with a printed report …
sudo .venv/bin/wiguard scan --duration 60

# 2b. … or the long-running sensor feeding the dashboard.
sudo .venv/bin/wiguard sensor
uv run wiguard api
```

`scan`, `sensor` and a live `enroll` accept `--save-pcap FILE`: every captured
packet is also written to a pcap, so the same run can be replayed later
(`wiguard replay`) with another configuration — e.g. for the baseline and
ablation runs of an experiment.

Enrollment is always an explicit command: learning automatically would also
learn an attacker who is already on the air.

## Commands

| Command | Purpose |
|---|---|
| `wiguard scan` | short live scan, prints APs and alerts (`--json` for machine output, `--save-pcap` to keep the capture) |
| `wiguard sensor` | continuous capture; writes the SQLite state database every flush (`--save-pcap` to keep the capture) |
| `wiguard enroll` | trusted profiles from a live capture (`--duration`) or a pcap (`--pcap`) |
| `wiguard analyze PCAP` | offline analysis of a capture |
| `wiguard replay PCAP` | offline analysis into a state database for the dashboard |
| `wiguard api` | read-only HTTP/WebSocket API (OpenAPI docs at `/docs`) |
| `wiguard fixtures generate DIR` / `evaluate MANIFEST` | synthetic scenarios and their scoring |

## Configuration

`config.yaml` is validated on load (unknown keys and out-of-range values are
errors) and every value is used. Precedence: command-line flag → `config.yaml`
→ built-in default. Use `--config` to point at another file.

## API

All endpoints are `GET`; the database is opened read-only on every request.

`/api/health`, `/api/stats`, `/api/sensor`, `/api/config`, `/api/trusted-profiles`,
`/api/aps`, `/api/aps/{bssid}`, `/api/aps/{bssid}/metrics`, `/api/aps/{bssid}/timeline`,
`/api/alerts`, `/api/alerts/{id}`, `/api/events`, `/api/timeline`,
`/api/export/{alerts,aps,events}.csv`, and the WebSocket `/api/live` for timeline updates.
The response models generate the OpenAPI document (`/docs`) and, from it, the
dashboard's TypeScript types (`make api-types`), so client and server cannot drift apart.

Alerts are incidents: one open alert per AP, updated while evidence keeps
arriving, escalated when the verdict gets worse, resolved after
`alert_resolve_seconds` without evidence.

## Development

```bash
make check          # everything CI runs: lint, types, tests (Python and dashboard)
make demo           # replay the classic Evil Twin scenario and serve it to the dashboard
make api-types      # after changing the API: regenerate openapi.json and the TS types
```

| Layer | Tools |
|---|---|
| Python | pydantic (config, API models, profile files), Typer + Rich (CLI), FastAPI, Scapy, stdlib `sqlite3` |
| Python quality | ruff (lint + format), mypy `--strict`, pytest, hypothesis (property-based tests) |
| Dashboard | React 19, TanStack Query (server state), React Router (one URL per view), openapi-fetch + generated types, Recharts |
| Dashboard quality | TypeScript strict, Biome (lint + format), Vitest + Testing Library |
| Delivery | uv (locked Python environment), GitHub Actions (`.github/workflows/ci.yml`) |

Synthetic scenarios validate detector logic, not radio-frequency reality; the
experimental evaluation on real hardware is planned in
[docs/THESIS-PLAN.md](docs/THESIS-PLAN.md).

## Project documents

- [Architecture and detection logic](docs/ARCHITECTURE.md)
- [Implementation status and roadmap](docs/PROJECT-ROADMAP.md)
- [Thesis plan and experimental method](docs/THESIS-PLAN.md)
- [Code review and rebuild, 30.10.2026](docs/audits/2026-10-30-przebudowa.md)
- [Audit checklist](docs/CLAUDE-REPO-AUDIT.md)
- Historical: [May 2026 development log](docs/history/wiguard-dev-log.md), [original concept v2](docs/history/wiguard-plan-v2.md) (not a list of shipped features)
