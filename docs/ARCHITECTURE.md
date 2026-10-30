# WiGuard — architektura i logika detekcji (stan: 30.10.2026)

Dokument opisuje **to, co jest zaimplementowane i przetestowane** w `src/wiguard`.
Może służyć jako materiał do rozdziałów 3–4 pracy. Liczby progów to wartości
domyślne z `config.yaml`.

## 1. Zasada działania

WiGuard jest pasywnym sensorem. Karta w trybie monitor przeskakuje po kanałach i
odbiera ramki zarządzające 802.11. Z ramek budowany jest profil każdego AP. Cztery
niezależne detektory szukają w profilach śladów podszywania się. Korelacja łączy
ich wyniki w jeden werdykt na AP i jedno zdanie wyjaśnienia.

System **niczego nie nadaje** i nie dotyka wewnętrznej karty Wi-Fi hosta. API jest
tylko do odczytu, a zaufane profile są zapisywane wyłącznie jawnym poleceniem
`wiguard enroll`.

## 2. Przepływ danych

```
pakiet ─► parse_frame ─► BeaconFrame ─┬─► APTracker (profil AP) ─┬─► IdentityVerifier ───────┐
                                      │                          └─► EnvironmentAnomaly ─────┤
                                      └─► DuplicateBSSIDDetector ─────────────────────────────┤─► CorrelationEngine ─► alerty
          ─► DisruptionFrame ─► DisruptionCounter ─► DeauthStormDetector ──────────────────────┘
```

| Warstwa | Pliki | Odpowiedzialność |
|---|---|---|
| Przechwytywanie | `capture/adapter.py`, `capture/engine.py` | tryb monitor, skakanie po kanałach, przywrócenie karty, kontrola, że Wi-Fi hosta nadal działa |
| Cechy | `features/*` | jeden parser ramek, fingerprint IE, zegar (TSF), sekwencje, interwał beaconów, liczniki deauth |
| Detekcja | `detection/*` | sygnały z poziomem ważności, zgrupowane w `DetectionEvent` |
| Korelacja | `correlation.py` | wynik, werdykt, wyjaśnienie |
| Potok | `pipeline.py` | spina wszystko; ten sam kod dla `scan`, `sensor`, `analyze`, `replay` i ewaluacji |
| Runtime | `runtime/store.py`, `runtime/sensor.py`, `runtime/replay.py` | baza SQLite, cykl życia alertów, sensor ciągły, odtwarzanie pcap |
| Interfejs | `api/*`, `dashboard/` | API tylko do odczytu, panel operatora |

**Model czasu.** Każda ramka niesie znacznik czasu przechwycenia z jądra/libpcap
(`packet.time`). Ten sam znacznik jest zapisany w pliku pcap, więc analiza nagrania
daje dokładnie ten sam wynik co analiza na żywo. `wiguard replay` dodatkowo
wywołuje ocenę co `flush_interval_seconds` czasu nagrania, tak jak sensor robi to w
czasie rzeczywistym: znaczniki alertów w powtórce odpowiadają chwilom, w których
sensor by je zgłosił (podstawa pomiaru TTD).

## 3. Cechy

| Cecha | Jak liczona | Po co |
|---|---|---|
| Fingerprint IE | SHA-256 z kolejności stabilnych elementów IE i treści kluczowych (rates, HT/VHT, RSN, extended caps, vendor); bez elementów zmiennych (TIM, BSS Load, CSA, Quiet). IE są parsowane z surowych bajtów TLV. | sprzęt i konfiguracja AP |
| Clock skew | regresja liniowa TSF AP względem lokalnego czasu; nachylenie − 1 w ppm. Spadek TSF (restart AP lub drugi nadajnik) zeruje okno estymatora. | oscylator konkretnego urządzenia |
| Numery sekwencyjne | arytmetyka numerów seryjnych (RFC 1982): krok w przód < 2048 to postęp, w przeciwnym razie skok wstecz | restart lub drugi nadajnik |
| Interwał i jitter beaconów | różnice TSF kolejnych beaconów zaokrąglone do wielokrotności interwału | konfiguracja AP |
| RSSI | średnia i odchylenie w oknie | położenie nadajnika |
| Deauth/disassoc | tempo w oknie przesuwnym 10 s, osobno broadcast i unicast | wypychanie klientów |

Statystyki IE i interwału liczone są tylko z beaconów (odpowiedzi na sondowanie
mają inny zestaw elementów i nie trzymają się harmonogramu).

## 4. Detektory i sygnały

Siła sygnału: **HIGH = 1,0**, **MEDIUM = 0,6**, **LOW = 0,3**.

| Moduł | Sygnał | Waga | Warunek |
|---|---|---|---|
| identity (profil zaufany) | `unknown_bssid_for_trusted_ssid` | HIGH | BSSID spoza profili rozgłasza SSID zaufanej sieci (≥ 10 ramek) |
| | `ie_fingerprint_changed` | HIGH | dominujący fingerprint ≠ zapisany |
| | `clock_skew_changed` | HIGH | \|Δskew\| ≥ 5 ppm |
| | `rssi_shifted` | MEDIUM | \|ΔRSSI\| ≥ max(12 dB, 4σ z enrollmentu) |
| | `sequence_backward_jump` | MEDIUM | więcej skoków wstecz niż podczas enrollmentu |
| identity (duplikat BSSID) | `duplicate_bssid_clock_split` | HIGH | dwa pasma rezyduów TSF: przerwa ≥ 10 ms i ≥ 4× szerokość pasma, pasma przeplatają się w czasie (≥ 4 przejścia) |
| | `duplicate_bssid_channel_conflict` | HIGH | ten sam BSSID nadaje na dwóch kanałach w nakładających się przedziałach czasu |
| | `duplicate_bssid_ie_split` | HIGH | pasma mają różne fingerprinty IE |
| | `duplicate_bssid_sequence_conflict` | MEDIUM | przy przełączeniu pasma numer sekwencyjny cofa się |
| | `duplicate_bssid_rssi_split` | MEDIUM | pasma różnią się RSSI o ≥ 10 dB |
| environment | `same_ssid_ie_fingerprint_outlier` | HIGH | fingerprint inny niż u większości AP z tym SSID (≥ 3 AP, większość ≥ 60%) |
| | `same_ssid_vendor_oui_outlier` | HIGH | odległość Jaccarda OUI ≥ 0,75 |
| | `same_ssid_ie_shape_outlier` | MEDIUM | odległość Jaccarda zbioru IE ≥ 0,45 |
| | `same_ssid_beacon_interval_outlier` | MEDIUM | różnica interwału ≥ 20 TU |
| deauth storm | `management_frame_rate_high` | HIGH | ≥ 10 deauth/s lub ≥ 5 disassoc/s |
| | `broadcast_flood` | HIGH | ≥ 5 ramek broadcast/s |
| | `targeted_unicast_burst` | MEDIUM | ≥ 5 ramek unicast/s |

Dlaczego dwa pasma muszą się **przeplatać**: restart AP również daje dwie proste
TSF (przed i po), ale jedna po drugiej. Bliźniak nadaje równocześnie z oryginałem,
więc obserwacje skaczą między pasmami.

Burza deauth jest śledzona jako **epizod** na BSSID (od pierwszej do ostatniej ramki
powyżej progu, nowy epizod po 60 s ciszy). Tysiąc ramek to jeden dowód, nie tysiąc.

## 5. Korelacja

**Wynik.** Moduł `m` z dowodem wnosi `e_m = w_m · s_m`, gdzie `s_m` to siła jego
najsilniejszego sygnału. Wkłady łączone są wzorem noisy-OR:

```
score = 1 − Π_m (1 − w_m · s_m)
```

* W obrębie modułu liczy się **tylko najsilniejszy sygnał**: sygnały jednego
  detektora zwykle mają wspólną przyczynę (np. `broadcast_flood` podnosi też ogólne
  tempo ramek), a sumowanie liczyłoby tę samą przyczynę kilka razy.
* Między modułami wynik rośnie z każdym niezależnym potwierdzeniem i nigdy nie
  przekracza 1. Nie ma ręcznej tabeli premii.
* Wynik jest **heurystyczną miarą siły dowodów, a nie skalibrowanym
  prawdopodobieństwem**. Panel pokazuje go jako `87/100`, nigdy jako procent.

**Wagi i progi** (`config.yaml`): identity 0,70, environment 0,60, deauth 0,55;
`suspicious` od 0,45, `evil_twin` od 0,80. Wagi wynikają z reguł projektowych, a
test `tests/test_correlation.py` pilnuje, żeby każda zmiana konfiguracji domyślnej
ich nie złamała:

| Reguła projektowa | Wyniki przy wagach domyślnych | Werdykt |
|---|---|---|
| jeden moduł, sygnał HIGH | 0,70 / 0,60 / 0,55 | suspicious (nigdy evil_twin) |
| dwa moduły, sygnały HIGH | I+E 0,88 · I+D 0,865 · E+D 0,82 | evil_twin |
| jeden moduł, tylko MEDIUM | 0,42 / 0,36 / 0,33 | info |
| dwa moduły, tylko MEDIUM | I+E 0,629 · I+D 0,611 · E+D 0,571 | suspicious |

**Powiązanie po SSID.** W klasycznym ataku bliźniak ma *własny* BSSID, a ramki
deauth są fałszowane z BSSID *prawdziwego* AP, żeby wypchnąć jego klientów.
Grupowanie wyłącznie po BSSID nigdy by tych faktów nie połączyło. Dlatego, jeśli AP
ma już dowód z identity lub environment, burza deauth na *innym* AP z tym samym
SSID trafia do jego dowodów jako zdarzenie powiązane (`linked_from`).

## 6. Stan, alerty i API

* **Alert = incydent na AP.** Jeden otwarty alert na BSSID: aktualizowany, dopóki
  napływają dowody; eskalowany, gdy werdykt się pogarsza (wpis na osi czasu);
  zamykany (`resolved`) po `alert_resolve_seconds` (300 s) bez dowodów.
* **Okno dowodów.** Na żywo dowód, którego ostatnia ramka jest starsza niż
  `evidence_window_seconds` (300 s), przestaje się liczyć — AP, który zniknął, nie
  podtrzymuje alertu w nieskończoność.
* **Zdarzenia surowe** zapisywane są przy pojawieniu się lub zmianie zestawu
  sygnałów, a nie przy każdym zapisie (co 5 s).
* **Historia metryk** (RSSI, skew) — próbka na AP przy każdym zapisie, w którym AP
  był słyszany; maksymalnie 2000 próbek na AP.
* **API** otwiera bazę SQLite w trybie `mode=ro` przy każdym żądaniu: fizycznie nie
  może niczego zmienić. Brak bazy = pusty stan, baza ze złym schematem = 503 z
  komunikatem.

## 7. Znane ograniczenia (do rozdziału o ograniczeniach)

* **Bez enrollmentu** przypadek „jeden legalny AP + bliźniak z nowym BSSID” jest
  niejednoznaczny: dwa AP z tym samym SSID to za mało na większość, a nie wiadomo,
  który jest prawdziwy. WiGuard zgłasza wtedy tylko burzę deauth (jeśli wystąpi) i
  w raporcie przypomina o enrollmencie.
* **Restart zaufanego AP** daje sygnał `sequence_backward_jump` (MEDIUM →
  `info`). To zamierzone: zdarzenie jest widoczne, ale nie jest alarmem.
* **Moduł environment** wymaga co najmniej trzech AP z tym samym SSID.
* **Czas lokalny** to zegar systemowy hosta; korekty NTP w trakcie pomiaru wpływają
  na estymację skew. Skew wymaga 50 próbek TSF na AP (przy skakaniu po 38 kanałach
  to kilka minut).
* **Progi** są wartościami projektowymi. Ich strojenie i ocena skuteczności należą
  do eksperymentów na prawdziwym RF (oddzielnie zbiór strojenia i testowy).

## 8. Weryfikacja

`pytest` (112 testów) obejmuje parser na rzeczywiście serializowanych ramkach,
każdą cechę, każdy detektor (także przypadki, które **nie** mogą alarmować: jeden
zegar, restart, zmiana kanału, jednorodna sieć firmowa), reguły projektowe
korelacji, konfigurację, cykl życia alertów, tryb tylko do odczytu, API i CLI.

Scenariusze syntetyczne (`tests/pcap_fixtures/synthetic`, generowane przez
`wiguard fixtures generate`):

| Scenariusz | Oczekiwany werdykt |
|---|---|
| `clean_single_ap`, `clean_enterprise_same_ssid` | clean (kontrole negatywne) |
| `ap_restart` | info |
| `ssid_clone_new_bssid`, `bssid_clone_same_channel`, `bssid_clone_other_channel`, `enterprise_outlier`, `deauth_storm_only` | suspicious |
| `classic_evil_twin`, `bssid_clone_with_deauth` | evil_twin |

To testy regresyjne logiki, a nie dowód skuteczności w eterze.
