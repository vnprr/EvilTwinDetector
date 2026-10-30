# WiGuard — stan projektu i plan zamknięcia Red/Blue (aktualizacja 30.10.2026)

> **Dokument operacyjny, źródło prawdy dla kolejnych prac.** Rozdziela stan *potwierdzony w kodzie i testach* od planowanych funkcjonalności. Nie przypisywać niezrealizowanym modułom statusu „gotowe”. Archiwalna wizja: [history/wiguard-plan-v2.md](history/wiguard-plan-v2.md).

## 0. Cel i ograniczenie zakresu

**Produkt/temat pracy:** niezależny, pasywny detektor fałszywych AP (Evil Twin), działający na zwykłych adapterach Wi-Fi, z wyjaśnialnymi alarmami. System ma zostać oceniony w powtarzalnym laboratorium.

- **Blue** — detektor, sensor, historia, evidence, dashboard i eksport.
- **Red** — **oddzielny laboratoryjny kontroler scenariuszy**, konfiguracja własnego AP / imitacji, kontrolowane testy odporności, kalendarz przebiegu, ground truth i porównanie wyników Blue.
- **Evaluator** — niezależnie ocenia alarmy Blue względem ground truth Red. Nie może podpowiadać Blue, że atak trwa.
- **Cel akademicki:** wykrywalność, czas detekcji, FPR/FNR, ablation i powtarzalność; nie pełny komercyjny WIPS czy platforma ofensywna.
- **Wymagania nienegocjowalne:** Red nie może wykonywać działań radiowych poza jawnie zatwierdzoną, izolowaną siecią laboratoryjną; brak przypadkowego użycia istniejącego interfejsu internetowego, brak auto-containment z poziomu Blue. Red domyślnie dry-run / disabled.

## 1. Stan kodu

- 30.10.2026 cały kod przeczytano i przebudowano od fundamentów; lista znalezionych błędów i zmian: [audits/2026-10-30-przebudowa.md](audits/2026-10-30-przebudowa.md). Architektura: [ARCHITECTURE.md](ARCHITECTURE.md).
- Bramki (uruchomione 30.10.2026, bez sprzętu radiowego): `pytest` 112 zaliczonych / 1 pominięty (wymaga nagrania z karty), `ruff` bez uwag, `wiguard fixtures evaluate` 10/10, dashboard typecheck + build, test w Chromium wszystkich widoków bez błędów konsoli.
- **NOT RUN:** przechwytywanie na żywo (brak karty w środowisku przeglądu). Na maszynie laboratoryjnej należy ponownie wykonać enrollment (zmienił się format fingerprintu IE) i użyć nowej bazy stanu (schemat 3).
- Dziennik z maja 2026 ([history/wiguard-dev-log.md](history/wiguard-dev-log.md)) opisuje poprzednią wersję kodu.

## 2. Macierz implementacji

| Obszar | Stan | Dowód |
|---|---|---|
| Adapter monitor mode (Alfa RTL8812AU), skakanie po kanałach, przywracanie karty | **ZAIMPLEMENTOWANE**, test sprzętowy z maja 2026 | `capture/*`, `docs/hardware/alfa-rtl8812au.md` |
| Parser ramek (beacon, probe response, deauth, disassoc; RadioTap; IE z surowych TLV) | **ZAIMPLEMENTOWANE** | `features/frames.py`, `tests/test_features.py` |
| Fingerprint IE, clock skew, sekwencje (RFC 1982), interwał beaconów, RSSI | **ZAIMPLEMENTOWANE** | `features/*` |
| Zaufane profile: jawny enrollment, dryf profilu, nieznany BSSID dla zaufanego SSID | **ZAIMPLEMENTOWANE** | `detection/identity.py`, `wiguard enroll` |
| Duplikat BSSID: dwa przeplatające się zegary, konflikt kanałów | **ZAIMPLEMENTOWANE** | `detection/duplicate.py` |
| Burze deauth/disassoc jako epizody | **ZAIMPLEMENTOWANE** (detekcja, nie generator) | `detection/deauth.py` |
| Porównanie z AP o tym samym SSID | **ZAIMPLEMENTOWANE, regułowe** | `detection/environment.py` |
| Korelacja noisy-OR, powiązanie po SSID, werdykty `info/suspicious/evil_twin` | **ZAIMPLEMENTOWANE**; wynik heurystyczny, **nie prawdopodobieństwo** | `correlation.py`, `tests/test_correlation.py` |
| Jeden potok dla scan / sensor / analyze / replay / ewaluacji | **ZAIMPLEMENTOWANE** | `pipeline.py` |
| `config.yaml` jako czynna konfiguracja z walidacją | **ZAIMPLEMENTOWANE** | `config.py`, `tests/test_config.py` |
| Sensor ciągły + SQLite, alert jako incydent (otwarcie/eskalacja/zamknięcie) | **ZAIMPLEMENTOWANE** | `runtime/*`, `tests/test_runtime.py` |
| Replay pcap z harmonogramem sensora (podstawa TTD) | **ZAIMPLEMENTOWANE** | `runtime/replay.py`, `wiguard replay` |
| API tylko do odczytu (SQLite `mode=ro`), WebSocket, eksport CSV, OpenAPI | **ZAIMPLEMENTOWANE** | `api/*` |
| Dashboard Blue (AP, alerty z dowodami per detektor, trendy, oś czasu, system) | **ZAIMPLEMENTOWANE** | `dashboard/` |
| Scenariusze syntetyczne + ewaluator z macierzą pomyłek | **ZAIMPLEMENTOWANE** (regresja, nie dowód skuteczności w eterze) | `evaluation/*`, `tests/pcap_fixtures/synthetic` |
| Active Verification DHCP/DNS/TCP, ML | **BRAK** (świadomie poza zakresem) | — |
| Dashboard Red + kontroler laboratorium, ground truth | **BRAK** | P2 |
| Eksperymenty na prawdziwym RF, drugi chipset | **BRAK WYNIKÓW** | P3 |

## 3. Priorytety wykonania

### P0 — Audyt bazowy i integralność — **ZAMKNIĘTE 30.10.2026**

- [x] Pełny przegląd kodu i bramek testowych (pkt 1).
- [x] Parsowanie TSF/RadioTap, czas, kanały, sekwencje, IE, liczniki, stany AP — poprawione i pokryte testami.
- [x] `config.yaml` jest jedynym źródłem wartości; test: zmiana progu zmienia wynik.
- [x] Korelacja: bez podwójnego liczenia, okna czasowe, cykl życia alertów, wynik nie nazywany prawdopodobieństwem.
- [x] Zaufane profile: tylko jawny enrollment, brak automatycznego zaufania, restart AP daje `info`, a nie alarm.
- [x] Runtime i API: API fizycznie tylko do odczytu, zapis w jednej transakcji, retencja metryk, czytelne błędy schematu.
- [x] README zgodne ze stanem faktycznym.

### P1 — Blue i ewaluator o wartości badawczej — **W WIĘKSZOŚCI ZAMKNIĘTE**

- [x] Model evidence: obserwacje → sygnały (z poziomem ważności i komunikatem) → zdarzenie modułu → alert z wyjaśnieniem.
- [x] Dashboard: stan sensora, lista AP, alerty z dowodami, trendy RSSI/skew, oś czasu, stany awarii/stale/replay, eksport.
- [x] Jawny enrollment zaufanych profili (`wiguard enroll`), bez „zaufaj” jednym kliknięciem.
- [x] Odtwarzalny replay pcap i eksport CSV/JSON.
- [x] Spójny kontrakt API (modele pydantic, OpenAPI) i testy API.
- [ ] Wersjonowanie/blokada pliku profili (np. podpis lub historia zmian) — opcjonalne.
- [ ] Analiza FP dla roamingu i zmian kanału na prawdziwym RF — należy do P3.

### P2 — Red Laboratory Controller i automatyzacja ground truth

- [ ] **Red Dashboard**: urządzenia laboratoryjne, scenariusze, wymagania wstępne, konfiguracja AP, przebieg eksperymentu, log działań, synchronizacja zegarów, stan/test zakończony/przerwane; możliwość przerwania i przywrócenia konfiguracji.
- [ ] Wyodrębnić adapter kontrolowania **własnego** AP przez oficjalne API/router laboratoryjny (np. MikroTik RouterOS REST lub OpenWrt ubus JSON-RPC); realizacja przez wąskie, walidowane polecenia zamiast dowolnych komend LLM.
- [ ] Scenariusze: legalny AP, legalny drugi AP z tym samym SSID, SSID clone, BSSID clone, same/different channel, AP restart, RSSI movement oraz różne profile security/PMF na sprzęcie testowym.
- [ ] Ground truth z **niezależnego kontrolera Red**: identyfikator próby, timestamp start/stop, prawdziwy/symulowany AP, konfiguracja urządzeń, wersje, klasa scenariusza, przebieg akcji i oczekiwany wpływ.
- [ ] Scenariusze deauth/disassociation **tylko jeśli potrzebne do pracy**, na własnym izolowanym AP i własnych klientach, z trybem domyślnie wyłączonym, jawną autoryzacją, ograniczeniem celu/czasu/tempa, natychmiastowym stop, logiem i recovery. Nie mieszać tego modułu z pasywnym sensorem Blue. Brak „disrupt all devices” lub niekontrolowanego skanu najbliższych sieci.
- [ ] Security: allowlista identyfikatorów **fizycznych** urządzeń AP/BSSID i interfejsów, oddzielone karty sieciowe, izolowany segment, jawne strefy radiowe/kanały, role operatora, audyt i fail-closed przy utracie kontroli.
- [ ] Ewaluator generuje confusion matrix oraz per-scenario detection, **TTD**, precision, recall, FPR/FNR, FP per godzina i porównuje timestampy bez udostępniania etykiet Blue w czasie działania.

**Kryterium wyjścia P2:** pojedynczy scenariusz można powtórzyć kilkukrotnie, otrzymać ground truth i obiektywnie porównać alerty. System nie może działać poza dozwolonym laboratorium.

### P3 — Badania i praca dyplomowa (najważniejsze)

- [ ] Zebrać próby normalne oraz scenariusze Evil Twin na rzeczywistym RF; fixture Scapy pozostają testem regresyjnym, nie dowodem skuteczności w środowisku radiowym.
- [ ] Wykonać *minimum* 4 doświadczenia: **(A)** stabilność fingerprintów i clock skew między sesjami, **(B)** skuteczność i TTD dla wariantów Evil Twin, **(C)** false positives w benign traffic, **(D)** ablation (bez poszczególnych modułów) względem bazowej kontroli SSID/BSSID.
- [ ] Sprzęt: obecny RTL8812AU + drugi chipset (np. MT7612U) + co najmniej dwa różne AP lub stosy; odnotować ograniczenia kompatybilności i próbki niedostępne. Karty i routery to **propozycje**, nie zakupione/zweryfikowane urządzenia.
- [ ] Oddzielić strojenie progów (calibration) od oceny końcowej (test); wykluczyć train/test leakage między sesjami i urządzeniami.
- [ ] Zdefiniować jednostkę zdarzenia/okna i etykiety, żeby nie raportować accuracy z milionów ramek jako liczby wykrytych ataków.
- [ ] Zapis wyników zawiera: wariant scenariusza, data/time, SHA kodu, wersje sterowników, AP/sensor, tabele i wykresy, niepewności/konfuzje i negatywne wyniki.
- [ ] Zaktualizować rozdziały 3–6 pracy na podstawie **rzeczywiście wdrożonego i sprawdzonego** systemu. Porównać Kismet/nzyme/rozwiązania enterprise uczciwie, bez deklarowania nieistniejącej nowości.

**Kryterium wyjścia P3:** powtarzalny eksperyment z kompletną metryką, analizą ograniczeń i wnioskami odpowiadającymi na pytania pracy.

## 4. Minimalny interfejs Red/Blue

**Jeden produkt webowy może mieć dwa osobne obszary**, ale nie należy mieszać poziomu dostępu:

| Blue / obrona | Red / laboratorium |
|---|---|
| AP inventory, sensor health, timeline | urządzenia i ich autoryzowany zakres |
| identity fingerprint / comparison | katalog scenariuszy i parametry |
| evidence i correlated alerts | plan uruchomienia, autoryzacja, dry-run |
| historia i baseline | sesja, status, ground truth |
| read-only monitoring | kontrola legalnego AP przez wąskie API |
| eksport CSV/JSON | stop/rollback/log i eksport |
| nigdy automatyczny deauth | test zakłócenia tylko odrębnie autoryzowany, opcjonalny |

**Zasada UX:** nie tworzyć dwóch niezależnych monolitów ani wielkich dashboardów; wspólna struktura danych, ale odseparowane endpointy uprawnień i odpowiedzialności. Red nie może ukrywać dowodów, że operacja nie powiodła się.

## 5. Kolejność i priorytety dyplomu

1. ~~Audyt i naprawy P0~~ (zamknięte 30.10.2026). Nie dodawać ML.
2. **Dane i Blue P1** — możliwość wyjaśnienia i odtworzenia alertu.
3. **Minimalny Red P2** do eksperymentów (nie framework pentestingowy).
4. **P3 badania** i opis systemu zgodny ze stanem faktycznym.
5. Opcjonalnie później: active DHCP/DNS verification, ML, edge deployments i commercial hardening — **tylko gdy nie blokują ukończenia pracy**.

## 6. Repo i dokumentacja

- Plan pracy: [THESIS-PLAN.md](THESIS-PLAN.md).
- Prompt audytu Claude: [CLAUDE-REPO-AUDIT.md](CLAUDE-REPO-AUDIT.md).
- [ARCHITECTURE.md](ARCHITECTURE.md) — architektura i logika detekcji.
- [history/wiguard-plan-v2.md](history/wiguard-plan-v2.md) — archiwalny plan wizyjny; **nie jest backlogiem realizacyjnym**.
- [history/wiguard-dev-log.md](history/wiguard-dev-log.md) — dziennik historyczny; wpis „testy zielone” = stan z daty wpisu.
- `README.md` — instrukcja uruchomienia / faktyczna funkcjonalność, nie lista marzeń.
