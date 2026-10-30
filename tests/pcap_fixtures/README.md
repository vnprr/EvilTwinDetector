# WiGuard pcap fixtures

`synthetic/` holds small captures of correctly formed 802.11 frames (beacons with
RadioTap RSSI/channel/TSFT, real RSN and vendor elements, deauthentication
floods) generated with Scapy, plus `manifest.json` with the expected verdict of
each scenario. `enroll_*.pcap` are the known-good captures the scenarios enroll
trusted profiles from. The tests check that the committed files match the
generator byte for byte.

```bash
wiguard fixtures generate tests/pcap_fixtures/synthetic
wiguard fixtures evaluate tests/pcap_fixtures/synthetic/manifest.json
```

Captures from real radio environments do not belong in Git unless deliberately
sanitised; keep them in `data/raw/` or `.wiguard/` (both ignored).
