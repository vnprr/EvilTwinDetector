# WiGuard — stan projektu i plan zamknięcia Red/Blue (26.10.2026)

> **Dokument operacyjny, źródło prawdy dla kolejnych prac.** Historyczny `wiguard-plan-v2.md` pozostaje materiałem koncepcyjnym. Ten dokument rozdziela stan *potwierdzony w kodzie main*, deklaracje z dawnych testów i planowane funkcjonalności. Nie przypisywać niezrealizowanym modułom statusu „gotowe”.

## 0. Cel i ograniczenie zakresu

**Produkt/temat pracy:** niezależny, w pierwszej kolejności pasywny detektor fałszywych AP (Evil Twin), działający na zwykłych adapterach Wi-Fi, z wyjaśnialnymi alarmami. System ma zostać oceniony w powtarzalnym laboratorium.

- **Blue** — detektor, sensor, historia, evidence, dashboard i eksport.
- **Red** — **oddzielny laboratoryjny kontroler scenariuszy**, konfiguracja własnego AP / imitacji, kontrolowane testy odporności, kalendarz przebiegu, ground truth i porównanie wyników Blue.
- **Evaluator** — niezależnie ocenia alarmy Blue względem ground truth Red. Nie może podpowiadać Blue, że atak trwa.
- **Cel akademicki:** wykrywalność, czas detekcji, FPR/FNR, ablation i powtarzalność; nie pełny komercyjny WIPS czy platforma ofensywna.
- **Wymagania nienegocjowalne:** Red nie może wykonywać działań radiowych poza jawnie zatwierdzoną, izolowaną siecią laboratoryjną; brak przypadkowego użycia istniejącego interfejsu internetowego, brak auto-containment z poziomu Blue. Red domyślnie dry-run / disabled.

## 1. Stan zdalnego repo

- Repo: `vnprr/EvilTwinDetector`, jedyna gałąź zdalna w dniu przeglądu: `main`. Brak zdalnej `claude/*` i brak PR do scalenia.
- **Kod bazowy oceniany:** `609b01e5606b903ff8043eb81f821f23acdcd643` (2026-05-07).
- Historyczny dziennik `wiguard-dev-log.md`: 49 testów backendu, 5/5 scenariuszy syntetycznych, frontend typecheck/build zaliczone **w maju 2026**. To **nie są wyniki świeżo uruchomionych testów**.
- Oczekiwana historyczna implementacja Claude (np. moduł live disconnect/deauth) **nie jest obecna w zdalnym main**. Sprawdzić lokalne `git branch -a`, `git reflog`, `git fsck --no-reflogs`, inne kopie i stash **zanim** stwierdzi się utratę kodu. Nie importować znalezionej gałęzi bez diffu, testów i kontroli bezpieczeństwa.
- Plik `wiguard-plan-v2.md` opisuje warianty jeszcze **niezaimplementowane**; stwierdzenia typu „zero-config”, „prawdopodobieństwo”, „4 moduły” i ML nie mogą być przenoszone do raportu z realizacji bez dowodów.

## 2. Macierz implementacji (kod main; stan historyczny)

| Obszar | Stan | Dowód / uwaga |
|---|---|---|
| Adapter monitor mode (Alfa RTL8812AU) | **ZAIMPLEMENTOWANE, historyczny smoke test** | `capture/*`, `docs/hardware/alfa-rtl8812au.md`; potwierdzić ponownie na docelowym Linux |
| Beacon/probe response, RadioTap, RSSI, kanał, TSF, BSSID | **ZAIMPLEMENTOWANE** | parser, state, `wiguard-scan` |
| IE fingerprint / vendor OUI / beacon timing / sequence | **ZAIMPLEMENTOWANE** | `features/*`, analyzer PCAP |
| Clock skew: rolling linear regression | **ZAIMPLEMENTOWANE** | nie mylić z walidacją stabilności na wielu urządzeniach |
| Jawny baseline i `APIdentityVerifier` | **ZAIMPLEMENTOWANE** | trzeba sprawdzić lifecycle, zmiany konfiguracji, restart i drift |
| Same-BSSID duplicate detector | **ZAIMPLEMENTOWANE** | residual split + dodatkowe potwierdzenie; niezależna walidacja RF konieczna |
| Deauth/disassoc *detection* | **ZAIMPLEMENTOWANE** | liczniki / `DeauthStormDetector`; nie jest to generator ramek |
| Same-SSID peer/environment anomaly | **ZAIMPLEMENTOWANE, regułowe** | nie HDBSCAN/ML |
| Correlation / alerty `info, suspicious, evil_twin` | **ZAIMPLEMENTOWANE** | scoring heurystyczny, a **nie skalibrowane prawdopodobieństwo** |
| Long-running sensor + SQLite | **ZAIMPLEMENTOWANE** | `runtime/*`, retencja/wyścigi/błędy do audytu |
| Read-only API FastAPI / WebSocket | **ZAIMPLEMENTOWANE** | `api/*` |
| Dashboard operatora / Blue (React + TS) | **MVP ZAIMPLEMENTOWANE** | widok AP/alertów/osi czasu; brak potwierdzenia jakości realnego UX |
| PCAP offline + syntetyczne fixture/evaluator | **ZAIMPLEMENTOWANE** | 5 scenariuszy syntetycznych to regresja, nie test skuteczności w eterze |
| `config.yaml` jako czynna konfiguracja | **NIEPOTWIERDZONE / ryzyko P0** | audyt wskazał brak czytnika YAML i rozbieżne domyślne wartości |
| Active Verification DHCP/DNS/TCP | **BRAK** | pusty `active/`; opcjonalne po zakończeniu ewaluacji pasywnej |
| ML / firmware classifier | **BRAK** | pusty `ml/`; nieobowiązkowe |
| Dashboard Red + kontroler laboratorium | **BRAK** | do zbudowania jako osobny obszar z izolacją i kontrolą uprawnień |
| Live deauth/disconnect lab-only | **BRAK na main** | istnieje analiza deauth i syntetyczne ramki; nie istnieje potwierdzony live injector |
| Systematyczne eksperymenty real RF, multi-chipset | **BRAK WYNIKÓW** | wymagane do pracy inżynierskiej |

## 3. Priorytety wykonania

### P0 — Audyt bazowy i integralność (bez dokładania funkcji)

- [ ] Zamrozić SHA bazowe, środowisko Python/Node/OS/driver, wykonać inwentaryzację modułów oraz zależności. Utworzyć tabelę **implemented / partially / missing / broken**, z odniesieniem do pliku, funkcji i testu.
- [ ] Ponownie uruchomić backend unit/integration, evaluator syntetyczny, typecheck/build frontendu, API smoke i dashboard smoke. Raportować `PASS/FAIL/SKIP/NOT RUN` i liczbę rzeczywiście wykonanych testów; jawnie pokazać hardware-only skippy.
- [ ] Sprawdzić wyjątkowości i poprawność parsowania TSF/Radiotap, monotonic time, kanałów, sekwencji, IE, management counters oraz stanów AP. Ujawnić różnice pomiędzy Scapy/danymi z różnych driverów.
- [ ] Rozstrzygnąć sprawę `config.yaml`: albo prawdziwy loader z walidacją, albo usunąć pozornie aktywne konfiguracje i mieć jedno źródło wartości. Test: zmiana progu w config faktycznie zmienia wynik detekcji.
- [ ] Zweryfikować reguły correlatora: wagowanie, podwójne liczenie zależnych sygnałów, okna czasowe, cooldown, deterministyczność, skale i nazewnictwo `confidence`. Nie nazywać wyniku prawdopodobieństwem bez kalibracji.
- [ ] Audyt baseline (explicit learning, untrusted start, restart, zmiana BSSID/SSID, poisoning, persistence), bez niewidocznego automatycznego zaufania.
- [ ] Runtime i API: SQLite locking/atomic updates, zamknięcie procesu, idempotencja, recovery, retencja, streaming, sanitizacja wejść, brak ekspozycji API na sieć publiczną bez kontroli.
- [ ] Uaktualnić README: nie nazywać projektu wyłącznie capture foundation, nie opisywać planowanych elementów jako istniejących.
- [ ] Zbadać lokalne/reflog ślady dawnej pracy Claude i oddzielnie ocenić, czy odzyskiwany kod warto integrować.

**Kryterium wyjścia P0:** odtwarzalne polecenia testowe, jawny status każdego testu i lista ryzyk z priorytetem. Bez przepisywania architektury „przy okazji”.

### P1 — Doprowadzić Blue i ewaluator do wartości badawczej

- [ ] Jednolita tożsamość sensora/AP, rozróżnienie SSID/BSSID/physically distinct emitter, jednoznaczne okna i znaczniki czasu.
- [ ] Przemyślany model evidence: obserwacje → sygnały → alert; jawne pochodzenie, czas, źródło i powody klasyfikacji, bez zawyżania pewności.
- [ ] Blue Dashboard: status sensora i interfejsu; lista AP, wykrytych anomalii i alertów; szczegóły dowodów, trend RSSI/TSF/clock, timeline i filtrowanie; stan awarii, stale-data, brak danych, reconnect WS; eksport.
- [ ] Funkcja zarządzania zaufanym baseline z jawnym enrollment/lock/wersjonowaniem (nie mylić z jednym kliknięciem „trusted” bez śladu).
- [ ] Odtwarzalny tryb offline/replay PCAP i eksport **CSV/JSON** wyników surowych, agregatów, alarmów i metadanych sesji.
- [ ] Minimum analityki: próg i zależność od miejsca, fałszywe alarmy dla legalnego roamingu/restartu/zmiany kanału, metryki capture loss i channel dwell.
- [ ] Spójny kontrakt API/DTO/websocket; testy integracyjne i E2E dashboardu na deterministycznych danych.

**Kryterium wyjścia P1:** operator rozumie *które obserwacje* spowodowały alert, a eksperymentator potrafi odtworzyć ocenę na tej samej próbce.

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

1. **Najpierw audyt i naprawy P0**. Nie dodawać nowych algorytmów/ML.
2. **Dane i Blue P1** — możliwość wyjaśnienia i odtworzenia alertu.
3. **Minimalny Red P2** do eksperymentów (nie framework pentestingowy).
4. **P3 badania** i opis systemu zgodny ze stanem faktycznym.
5. Opcjonalnie później: active DHCP/DNS verification, ML, edge deployments i commercial hardening — **tylko gdy nie blokują ukończenia pracy**.

## 6. Repo i dokumentacja

- Plan pracy: [THESIS-PLAN.md](THESIS-PLAN.md).
- Prompt audytu Claude: [CLAUDE-REPO-AUDIT.md](CLAUDE-REPO-AUDIT.md).
- `wiguard-plan-v2.md` — archiwalny plan wizyjny; **nie jest backlogiem realizacyjnym**.
- `wiguard-dev-log.md` — dziennik historyczny; wpis „testy zielone” = stan z daty wpisu.
- `README.md` — instrukcja uruchomienia / faktyczna funkcjonalność, nie lista marzeń.
