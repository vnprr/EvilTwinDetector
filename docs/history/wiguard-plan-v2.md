# WiGuard — Plan Realizacji Projektu Inżynierskiego (v2)

> **ARCHIWUM KONCEPCJI (stan projektu z maja 2026).** Ten plik opisuje zarówno wykonane prace, jak i ambicje jeszcze niezrealizowane. Nie używać go jako aktualnej macierzy funkcji. W szczególności: *zero-config*, Active Verification, ML, pełna ewaluacja i Red Dashboard **nie są potwierdzone jako wdrożone w main**. Aktualny stan i backlog: [docs/PROJECT-ROADMAP.md](docs/PROJECT-ROADMAP.md). Zaktualizowany plan pracy dyplomowej: [docs/THESIS-PLAN.md](docs/THESIS-PLAN.md). Dokument audytu: [docs/CLAUDE-REPO-AUDIT.md](docs/CLAUDE-REPO-AUDIT.md).



## Wykrywanie Fałszywych Punktów Dostępu (Evil Twin) metodą Multi-Layer Fingerprinting

---

## 1. Wizja Projektu

### Co to jest
System pasywnego wykrywania fałszywych punktów dostępu WiFi, działający w czasie rzeczywistym bez wcześniejszego treningu ani konfiguracji. Sensor nasłuchuje ramek 802.11 w trybie monitorowym, buduje wielowymiarowy fingerprint każdego AP w zasięgu, koreluje sygnały z wielu warstw detekcji i — w razie podejrzenia — może aktywnie zweryfikować podejrzany AP przez warstwę sieciową.

### Czym się wyróżnia
- **Zero-config** — nie wymaga whitelisty, bazy znanych AP, ani fazy uczenia
- **Multi-warstwowe fingerprinting** — łączy cechy fizyczne (clock skew), protokołowe (IE structure), behawioralne (deauth patterns), środowiskowe (peer comparison) i sieciowe (aktywna weryfikacja)
- **Korelacja sygnałów** — jeden moduł alertuje, system szuka potwierdzenia w pozostałych (np. deauth flood + nowy AP z obcym fingerprint = wysoka pewność)
- **Explainable alerts** — system precyzyjnie wskazuje *które* cechy się nie zgadzają, z jakiego modułu pochodzi sygnał i z jakim prawdopodobieństwem
- **Lekki deployment** — laptop lub Raspberry Pi z kartą WiFi, zero infrastruktury

### Architektura wysokopoziomowa

```
┌──────────────────────────────────────────────────────────────────┐
│                        WiGuard System                            │
│                                                                  │
│  ┌───────────┐    ┌───────────────┐    ┌──────────────────────┐  │
│  │  Capture   │───▶│   Feature     │───▶│   AP State Manager   │  │
│  │  Engine    │    │  Extraction   │    │   (per-BSSID         │  │
│  │  (Scapy)   │    │  Pipeline     │    │    rolling window)   │  │
│  └───────────┘    └───────────────┘    └──────────┬───────────┘  │
│                                                   │              │
│          ┌────────────────┬───────────────┬────────┤              │
│          │                │               │        │              │
│   ┌──────▼───────┐ ┌─────▼──────┐ ┌──────▼─────┐ ┌▼───────────┐ │
│   │   Moduł 1    │ │  Moduł 2   │ │  Moduł 3   │ │  Moduł 4   │ │
│   │ AP Identity  │ │  Deauth    │ │ Environment│ │  Active    │ │
│   │ Verification │ │  Storm     │ │ Anomaly    │ │ Verificat. │ │
│   │              │ │  Detection │ │ (Clustering│ │ (on-demand)│ │
│   │ - clock skew │ │            │ │  + opcja   │ │            │ │
│   │ - IE fingerp.│ │            │ │    ML)     │ │ - DHCP     │ │
│   │ - seq numbers│ │            │ │            │ │ - DNS      │ │
│   │ - RSSI prof. │ │            │ │            │ │ - TCP/IP   │ │
│   └──────┬───────┘ └─────┬──────┘ └──────┬─────┘ └──┬─────────┘ │
│          │               │               │           │           │
│          └───────┬───────┴───────┬───────┘───────────┘           │
│                  │               │                                │
│          ┌───────▼───────────────▼──────┐                        │
│          │   Alert Correlation Engine   │                        │
│          │   (korelacja między modułami,│                        │
│          │    scoring, deduplikacja)    │                        │
│          └──────────────┬──────────────┘                        │
│                         │                                        │
│               ┌─────────▼──────────┐                             │
│               │   REST API /       │                             │
│               │   WebSocket        │                             │
│               └─────────┬──────────┘                             │
│                         │                                        │
└─────────────────────────┼────────────────────────────────────────┘
                          │
                ┌─────────▼──────────┐
                │   Dashboard / CLI  │
                └────────────────────┘
```

### Kluczowa zmiana w myśleniu: korelacja zamiast izolacji

Żaden moduł nie jest "ostateczną odpowiedzią" sam w sobie. Wartość systemu tkwi w korelacji:
- Moduł 1 mówi: "widzę dwa urządzenia z tym samym BSSID"
- Moduł 2 mówi: "właśnie widziałem deauth flood na tym kanale"
- Moduł 3 mówi: "nowy AP ma fingerprint typowy dla hostapd, reszta w otoczeniu to Cisco"
- Moduł 4 potwierdza: "DHCP za tym AP daje inny lease time niż reszta sieci"

Każdy sygnał osobno mógłby być false positive. Razem — to atak.

---

## 2. Etapy Realizacji

---

### ETAP 0: Środowisko i Fundament (tydzień 1)

**Cel:** Działający setup — karta Alfa w monitor mode na Linuksie, Scapy łapie surowe ramki 802.11 z RadioTap headers (w tym TSF timestamp).

**Zadania:**
- Konfiguracja karty Alfa w trybie monitorowym (airmon-ng / iw)
- Weryfikacja chipsetu i drivera — jeśli RTL8812AU, zainstalować driver `aircrack-ng/rtl8812au`
- Weryfikacja że Scapy odbiera ramki Dot11 z warstwy RadioTap (w tym TSF!)
- Channel hopping — implementacja przeskakiwania między kanałami (2.4 GHz: 1–13, 5 GHz: 36–165)
- Prosty skrypt: wyświetl SSID, BSSID, kanał, siłę sygnału, TSF każdego AP w zasięgu
- Setup repozytorium (Git), struktura projektu, virtualenv, requirements.txt
- Dokumentacja sprzętowa: model karty, chipset, driver, wersja jądra

**Struktura projektu od dnia 1:**
```
wiguard/
├── src/
│   ├── capture/          # Przechwytywanie ramek + channel hopping
│   ├── features/         # Ekstrakcja cech (clock skew, IE, RSSI, seq)
│   ├── detection/        # Moduły detekcji (4 moduły)
│   ├── correlation/      # Alert Correlation Engine
│   ├── ml/               # Opcjonalny klasyfikator firmware
│   ├── state/            # AP State Manager
│   ├── active/           # Active Verification (DHCP, DNS, TCP/IP)
│   ├── api/              # REST + WebSocket
│   └── utils/            # Helpers, logging, config
├── dashboard/            # Frontend React (prosty, funkcjonalny)
├── experiments/          # Skrypty eksperymentalne, Jupyter notebooki
├── data/                 # Zebrane pcapy, wyekstrahowane cechy
│   ├── raw/              # Surowe pliki .pcap
│   ├── processed/        # Wyekstrahowane feature vectors
│   └── labels/           # Ground truth etykiety eksperymentów
├── models/               # Wytrenowane modele ML (opcjonalnie)
├── tests/                # Testy jednostkowe i integracyjne
│   ├── unit/
│   ├── integration/
│   └── pcap_fixtures/    # Pcapy do testów regresji
├── docs/                 # Dokumentacja
├── config.yaml           # Konfiguracja systemu (thresholds, parametry)
└── README.md
```

**Realne problemy na tym etapie:**
- Nie każdy chipset karty Alfa dobrze współpracuje z Scapy w monitor mode. Pierwsza rzecz do sprawdzenia — jeśli to nie działa, trzeba zmienić driver lub kartę, zanim cokolwiek dalej.
- Scapy domyślnie nie widzi RadioTap headers na niektórych konfiguracjach — może wymagać `conf.use_pcap = True` lub sniffowania przez `tcpdump` z pipe do Scapy.
- **Krytyczny test:** Czy TSF timestamp jest obecny w przechwyconych ramkach? Bez tego clock skew nie zadziała. Sprawdzić przez: `pkt[RadioTap].timestamp` lub zdekodować RadioTap header ręcznie. Jeśli driver nie dostarcza TSF — trzeba szukać innego drivera lub karty.
- Channel hopping — karta w monitor mode nasłuchuje na jednym kanale. Trzeba implementować przeskakiwanie co ~200–500ms. Dłuższe okno na kanale = lepsze dane do clock skew, ale wolniejsze discovery.

**Deliverable:** Skrypt który wypisuje listę AP (SSID, BSSID, kanał, RSSI, TSF) aktualizowaną w real-time, z channel hoppingiem. Potwierdzenie że TSF jest dostępne.

---

### ETAP 1: Feature Extraction Pipeline (tygodnie 2–3)

**Cel:** Dla każdej ramki beacon/probe response wyekstrahować pełny zestaw cech tworzących fingerprint AP. Dodatkowo: zliczanie ramek zarządzania (deauth/disassoc) per-BSSID i per-kanał.

#### 1A. Clock Skew Estimation (kluczowa cecha)

**Teoria:**
Każdy beacon frame zawiera pole TSF (Timing Synchronization Function) — 64-bitowy timestamp w mikrosekundach, inkrementowany przez lokalny oscylator AP. Odbiorca rejestruje swój lokalny czas otrzymania ramki. Regresja liniowa TSF vs czas lokalny daje nachylenie (slope) — to jest clock skew, unikalne dla fizycznego urządzenia. Atakujący musiałby mieć identyczny kryształ kwarcowy, co jest w praktyce niemożliwe.

**Implementacja:**
```
Dla każdego BSSID:
1. Zbierz pary (TSF_i, local_time_i) z kolejnych beaconów
2. Po zebraniu N próbek (min. 50), oblicz regresję liniową (least squares)
3. Nachylenie (slope) = clock skew (typowo rzędu 1 ± kilka ppm)
4. R² powinno być bardzo bliskie 1.0 (zegar jest liniowy)
5. Residuals — odchylenia od prostej — informują o szumie i potencjalnych duplikatach
6. Aktualizuj przyrostowo (sliding window ostatnich M próbek)
```

**Realne problemy:**
- **Precyzja zegara odbiorcy.** `time.time()` w Pythonie ma jitter schedulera OS rzędu 10–100μs. Rozwiązanie: użyć `time.clock_gettime(CLOCK_MONOTONIC_RAW)` — unika korekty NTP i daje stabilny zegar. Alternatywa: timestamp z RadioTap header jeśli driver go dostarcza (zależne od chipsetu).
- **Channel hopping zaburza ciągłość.** Gdy karta przeskoczy na inny kanał, tracisz beacony z obecnego. Rozwiązanie: dłuższe okno na kanale (500ms) lub dwie karty — jedna na discovery, druga na pomiar stałego kanału. Dylemat designowy wart opisania w pracy.
- **Potrzebna ilość próbek.** Z literatury (Jana & Kasera, 2008): 100 beaconów (~10 sekund) daje ±0.5 ppm, 300+ beaconów (~30 sekund) daje bardzo stabilny wynik. Do zweryfikowania empirycznie — materiał na eksperyment.
- **Wielokrotne AP na tym samym BSSID.** Jeśli evil twin nadaje z tego samego BSSID, ich beacony mieszają się. Residuals regresji będą bimodalne (dwa zegary). To jest jednocześnie problem i sygnał diagnostyczny — opisane w Module 1.

#### 1B. Information Element Fingerprint

**Teoria:**
Beacon frame zawiera sekwencję Information Elements (IE) — tagowanych pól o zmiennej długości. Standard 802.11 definiuje ~80 typów IE, ale każdy vendor/firmware generuje je inaczej: inna kolejność, inne wartości, inne vendor-specific IE (ID 221). To jest jak user-agent przeglądarki — identyfikuje implementację.

**Implementacja:**
```
Z każdego beacon frame wyekstrahuj:
- Listę IE IDs w kolejności występowania → "sequence signature"
- Wartości kluczowych IE:
  - Supported Rates (IE 1) + Extended Supported Rates (IE 50)
  - HT Capabilities (IE 45) — flagi, MCS set
  - VHT Capabilities (IE 191) — jeśli obecne
  - RSN Information (IE 48) — cipher suites, AKM suites
  - Extended Capabilities (IE 127) — bitfield
  - Vendor Specific (IE 221) — OUI + dane (kluczowe!)
- Hash z powyższego → "IE fingerprint hash"
  (deterministyczny hash, np. SHA-256 z kanonizowanej struktury)
```

**IE do WYKLUCZENIA z fingerprintu (dynamicznie zmienne):**
- TIM (IE 5) — Traffic Indication Map, zmienia się co beacon
- Channel Switch Announcement (IE 37) — tymczasowe
- Quiet (IE 40) — tymczasowe
- BSS Load (IE 11) — zmienia się z obciążeniem

**Realne problemy:**
- AP może rotować vendor-specific IE między beaconami (nie wszystkie mieszczą się w jednej ramce). Rozwiązanie: fingerprint budować z unii IE z ostatnich N beaconów, nie z pojedynczej ramki.
- Aktualizacja firmware zmieni IE fingerprint. System powinien to tolerować — ale flagować zmianę.

#### 1C. Dodatkowe cechy per-beacon

- **RSSI statistics:** średnia, σ, min/max z okna czasowego — charakteryzuje pozycję i moc nadajnika
- **Beacon interval jitter:** deklarowany interval (zwykle 100 TU = 102.4ms) vs rzeczywisty. Sprzętowe AP trzymają się ściśle, software'owe (hostapd) mogą mieć większy jitter z powodu schedulingu OS
- **Sequence number analysis:** 802.11 sequence numbers (0–4095) rosnące monotonicznie. Dwa urządzenia z tym samym BSSID będą miały niezależne sekwencje — skoki, duplikaty, resety to sygnały diagnostyczne

#### 1D. Ramki zarządzania (management frames)

Oprócz beaconów, system musi przechwytywać i zliczać:
- **Deauthentication frames** (subtype 0x0C) — kto wysyła, do kogo (broadcast vs unicast), ile na sekundę
- **Disassociation frames** (subtype 0x0A) — j.w.
- **Probe responses** — ich IE fingerprint też wchodzi do profilu AP

To nie jest feature extraction per-AP, ale per-kanał / per-sieć — zasila Moduł 2.

**Deliverable:** Moduł `FeatureExtractor` produkujący `APFeatureVector` z każdej ramki. Moduł `APStateManager` agregujący wektory per-BSSID z sliding window. Moduł `ManagementFrameCounter` zliczający deauth/disassoc per-kanał i per-BSSID.

---

### ETAP 2: Detection Engine — 4 Moduły (tygodnie 3–5)

**Cel:** Cztery niezależne moduły detekcji + correlation engine.

---

#### Moduł 1: AP Identity Verification

**Co robi:** Śledzi tożsamość fizyczną każdego AP w czasie. Wykrywa zarówno jednoczesne duplikaty (dwa urządzenia nadają z tym samym BSSID) jak i sekwencyjne podmiany (to samo BSSID, ale nagle inne cechy fizyczne).

**Scenariusz A — Jednoczesny duplikat (evil twin działa równolegle z prawdziwym AP):**

```
1. Zbierz N beaconów z danego BSSID
2. Wykonaj regresję liniową TSF vs local_time
3. Oblicz residuals (odchylenie każdej próbki od prostej)
4. Jeśli residuals mają bimodalny rozkład → potencjalny duplikat
   Detekcja bimodalności: test Hartigana (dip test) lub prosty
   test na obecność dwóch klastrów w residuals
5. Klasteryzacja (k=2) na residuals → podział na dwa źródła
6. Osobna regresja na każdym klastrze → dwa clock skew
7. Test istotności różnicy (t-test lub z-test)
8. Dodatkowe potwierdzenie:
   - Czy sequence numbers wykazują dwa niezależne ciągi?
   - Czy IE fingerprint jest identyczny w obu klastrach?
   - Czy RSSI wykazuje bimodalność? (dwa nadajniki w różnych miejscach)
```

**Scenariusz B — Sekwencyjna podmiana (evil twin zastępuje prawdziwy AP):**

```
Utrzymuj rolling window (np. 5 minut) profilu AP:
  - Bieżący clock skew ± uncertainty
  - Bieżący IE fingerprint hash
  - Bieżące RSSI μ ± σ
  - Bieżący sequence number trend

Alarmy:
  - Clock skew zmienił się nagle o > Δ_threshold
    → fizyczna podmiana urządzenia (inny kryształ)
  - IE fingerprint hash się zmienił
    → inna implementacja / firmware  
  - RSSI skoczyło o > X dB
    → inna lokalizacja nadajnika
  - Sequence numbers zresetowane + clock skew zmieniony
    → podmiana (nie restart — restart zachowuje clock skew)

Metoda: CUSUM (Cumulative Sum) na clock skew dla wykrywania
change pointów, z-score na RSSI i beacon jitter.
```

**Kluczowe rozróżnienie: restart vs podmiana.**
Po restarcie AP: sequence numbers się resetują, TSF restartuje od 0, ALE clock skew (dryft kryształu) pozostaje ten sam — to ten sam sprzęt. Po podmianie: clock skew się zmienia, bo to inny kryształ. To rozróżnienie trzeba zaimplementować i jest warte opisania w pracy jako mechanizm redukcji false positives.

**Realne problemy:**
- Kalibracja thresholdu clock skew delta — za niski = FP z szumu pomiarowego, za wysoki = miss przy urządzeniach z podobnym dryftem. W pracy: opis empirycznej kalibracji.
- Przy channel hopping z jedną kartą, dane z jednego AP przychodzą przerywanie — sliding window musi to obsłużyć (gaps w danych).

---

#### Moduł 2: Deauth Storm Detection

**Co robi:** Wykrywa anomalny wzrost ramek deauthentication/disassociation, który jest typowym prekursorem lub towarzyszem ataku evil twin. Atakujący wysyła deauth flood żeby odłączyć klientów od prawdziwego AP i zmusić ich do połączenia z fałszywym.

**Dlaczego to ważne:** To jest moduł którego brakowało w pierwotnym planie, a jest oczywisty w kontekście real-world ataków. Większość evil twin attack toolkitów (airgeddon, fluxion, wifiphisher) domyślnie uruchamia deauth flood przed postawieniem fałszywego AP.

**Implementacja:**

```
Zliczaj ramki deauth/disassoc per kanał per okno czasowe (np. 10 sekund):

  deauth_rate = count(deauth_frames) / window_seconds

Normalne środowisko: sporadyczne deauth (< 1/s)
Atak: dziesiątki lub setki deauth/s na jednym kanale

Alarmy:
  - deauth_rate > threshold (np. 10/s) → deauth flood
  - Dodatkowy kontekst:
    - Czy deauth są broadcast (FF:FF:FF:FF:FF:FF) czy unicast?
      Broadcast = flood, unicast = targetowany atak
    - Czy source BSSID w deauth odpowiada realnemu AP?
      Atakujący spoofuje BSSID prawdziwego AP w deauth frames
    - Czy po fali deauth pojawia się nowy AP z tym samym SSID?
      → Korelacja z Modułem 1 i 3 → bardzo wysoka pewność ataku
```

**Korelacja z innymi modułami — to jest kluczowe:**
Deauth flood sam w sobie może mieć inne przyczyny (interference, bug w AP). Ale deauth flood PLUS nowy AP z obcym fingerprint PLUS clock skew nie pasuje = korelacja trzech modułów = prawie na pewno atak.

**Realne problemy:**
- W zatłoczonym środowisku (konferencja, hotel) deauth rate może być podwyższony naturalnie. Threshold musi być adaptacyjny lub konfigurowalny.
- 802.11w (Protected Management Frames / PMF) sprawia że deauth flood nie działa na nowoczesnych sieciach WPA3. System powinien sprawdzić czy AP obsługuje PMF (z IE RSN) i odpowiednio dostosować wagę tego modułu — jeśli sieć ma PMF, deauth flood jest mniej prawdopodobny.
- Atakujący może nie używać deauth flood (np. cierpliwy evil twin który czeka aż klienci sami się podłączą). Dlatego ten moduł jest jednym z czterech, nie jedynym.

---

#### Moduł 3: Environment Anomaly Detection (Peer Comparison)

**Co robi:** Porównuje fingerprint każdego AP z innymi AP w otoczeniu. W środowisku firmowym gdzie masz 20 AP tego samego vendora, AP na hostapd będzie naturalnym outlierem. Nie wymaga żadnych danych treningowych — działa na żywych danych z otoczenia.

**Podejście 1: Unsupervised Clustering (główne)**

```
Dla wszystkich AP widocznych w otoczeniu:
1. Wyekstrahuj wektor cech z IE fingerprint:
   - IE sequence signature (jako numerical encoding)
   - Supported rates vector
   - Capability flags
   - Vendor IE OUI set
   - Beacon interval
   - HT/VHT capabilities
   
2. Clustering (HDBSCAN lub DBSCAN):
   - HDBSCAN jest lepszy bo nie wymaga z góry liczby klastrów
   - Automatycznie identyfikuje outlierów (noise points)
   
3. AP które:
   - Są outlierami w clustering → podejrzane
   - Rozgłaszają SSID zgodne z dominującym klastrem
     ale nie należą do tego klastra → wysoce podejrzane
```

**Podejście 2: ML Firmware Classifier (opcjonalne rozszerzenie)**

```
Random Forest / XGBoost trenowany na cechach IE:
  Klasy: {enterprise_vendor, hostapd, openwrt, windows_softap, unknown}
  
Dane treningowe:
  - Beacony zbierane z kampusu/miasta (OUI jako etykieta vendor)
  - Hostapd w kilku konfiguracjach (ręcznie etykietowane)
  - Publiczne pcapy (Wireshark samples, CTF captures)
  → Jedno popołudnie zbierania + etykietowania

Użycie:
  - Klasyfikacja nowego AP → "ten AP twierdzi że jest firmowy,
    ale beacon wygląda jak hostapd z p=0.94"
  - Feature importance → które cechy IE najlepiej rozróżniają
    (materiał na sekcję eksperymentalną pracy)
```

**Relacja clustering vs ML:**
Clustering działa od razu, bez danych, ale daje tylko "ten AP jest inny". ML daje konkretną odpowiedź "to hostapd", ale wymaga danych treningowych. Oba mogą współistnieć. W pracy — porównanie obu podejść to materiał na eksperyment.

**Realne problemy:**
- W heterogenicznym środowisku (kawiarnia z 30 AP od 15 vendorów) clustering może nie wyłapać hostapd jako outliera — bo wszystko jest outlierem. System powinien uwzględniać kontekst: w sieci firmowej (wiele AP z tym samym SSID) clustering jest silny, w środowisku publicznym słabszy. Waga modułu zależy od kontekstu.
- Encoding IE sequence do wektora numerycznego — trzeba wybrać sensowną reprezentację. Opcje: bag-of-IEs (binary vector: czy IE typu X jest obecny), ordered sequence (position encoding), n-gramy IE IDs.

---

#### Moduł 4: Active Verification (on-demand)

**Co robi:** Aktywnie łączy się z podejrzanym AP i fingerprints infrastrukturę sieciową za nim. Nie odpala się na każdym AP — tylko na tych oznaczonych jako podejrzane przez Moduły 1–3. To jest "second opinion" który potwierdza lub obala podejrzenie.

**Dlaczego to wypadło z v1 i dlaczego wraca:**
W pierwszej wersji planu opisywałem warstwę sieciową (DHCP, DNS, TCP/IP) a potem ją zgubiłem. To błąd — evil twin musi mieć *za sobą* inną infrastrukturę sieciową niż prawdziwy AP, i tego nie da się sfałszować bez ogromnego wysiłku.

**Implementacja:**

```
Gdy AP jest flagowany jako podejrzany (score > threshold):
1. Połącz się z podejrzanym AP (druga karta WiFi lub ta sama po odłączeniu sensora)
2. Zbierz fingerprint DHCP:
   - Opcje DHCP w OFFER (kolejność, wartości)
   - Lease time
   - Gateway IP, DNS server IP
   - Domain name
3. Zbierz fingerprint DNS:
   - Czas odpowiedzi na zapytania
   - Czy DNS odpowiada na known-good domains poprawnie?
   - Czy są przekierowania? (captive portal = częsty evil twin pattern)
4. TCP/IP fingerprint:
   - TTL pakietów od gateway
   - TCP window size, opcje
   - Latencja do gateway vs latencja do internetu
5. Porównaj z profilem prawdziwego AP (jeśli wcześniej zebrano)
   lub z ogólnymi oczekiwaniami (np. "firmowy DHCP daje lease 8h,
   ten daje 1h — podejrzane")
```

**Realne problemy:**
- **Wymaga drugiej karty WiFi** (albo przerwania monitoringu pasywnego). Sensor nie może jednocześnie nasłuchiwać w monitor mode i być połączony z AP. Rozwiązania: (a) druga karta (tania USB WiFi), (b) tymczasowe przełączenie na managed mode, (c) osobne urządzenie (telefon) kontrolowane przez API.
- **Połączenie z evil twin jest potencjalnie niebezpieczne** — atakujący widzi że ktoś się łączy. Mitygacja: używać losowego MAC, nie wysyłać żadnego ruchu poza DHCP/DNS probe, rozłączyć się szybko.
- **Nie zawsze możliwe** — jeśli AP wymaga hasła którego nie znamy, nie możemy się połączyć. Moduł działa głównie na otwartych sieciach lub sieciach których hasło znamy (firmowa sieć).
- To jest moduł "nice-to-have" — system działa bez niego (Moduły 1–3 wystarczają), ale active verification dodaje warstwę pewności i materiał do pracy.

---

#### Alert Correlation Engine

**Co robi:** Łączy sygnały ze wszystkich modułów, oblicza skoelowany score, deduplikuje alerty i buduje timeline zdarzeń.

```
Każdy moduł produkuje surowy alert:
  {
    "module": "identity_verification" | "deauth_storm" | 
              "environment_anomaly" | "active_verification",
    "bssid": "AA:BB:CC:DD:EE:FF",
    "ssid": "FirmNetwork",
    "severity": 0.0–1.0,
    "confidence": 0.0–1.0,
    "evidence": { ... szczegóły zależne od modułu ... },
    "timestamp": "2025-01-15T14:23:01Z"
  }

Correlation Engine:
  1. Grupuje alerty per-BSSID w oknie czasowym (np. 5 minut)
  2. Oblicza correlated score:
     - Jeden moduł: score = severity × confidence × module_weight
     - Dwa moduły: score wzrasta ponadliniowo (korelacja = wzmocnienie)
     - Trzy+ moduły: bardzo wysoki score
  3. Reguły korelacji (przykłady):
     - deauth_flood + nowy AP z obcym fingerprint → score × 2.0
     - duplicate_bssid + firmware_mismatch → score × 1.8
     - clock_skew_change + deauth_flood + environment_outlier → score × 3.0
  4. Deduplikacja: nie alertuj 100 razy o tym samym AP
  5. Eskalacja: jeśli score rośnie w czasie → zwiększ severity
  6. Wyjaśnienie: human-readable opis "dlaczego ten alert"

Output:
  {
    "alert_id": "uuid",
    "bssid": "AA:BB:CC:DD:EE:FF",
    "ssid": "FirmNetwork",
    "final_score": 0.92,
    "classification": "evil_twin" | "suspicious" | "info",
    "contributing_modules": ["identity_verification", "deauth_storm"],
    "explanation": "Dwa urządzenia nadają z BSSID AA:BB:CC:DD:EE:FF 
      (clock skew 12.3 vs 16.5 ppm). Jednocześnie wykryto deauth flood
      (47 ramek/s) na kanale 6. IE fingerprint nowego źródła wskazuje 
      na hostapd, podczas gdy oryginał ma profil Cisco.",
    "timeline": [ ... sekwencja zdarzeń ... ]
  }
```

**Deliverable:** Cztery moduły detekcji + correlation engine. System wykrywa evil twin w kontrolowanym teście laboratoryjnym z wyjaśnieniem multi-modułowym.

---

### ETAP 3: Klasyfikator Firmware — Opcjonalny Komponent ML (tygodnie 5–6)

**Cel:** Model ML który na podstawie cech beacon frame określa platformę/firmware AP. Jest rozszerzeniem Modułu 3, nie fundamentem systemu — system działa bez niego (clustering wystarczy), ale ML daje konkretniejszą odpowiedź i materiał na eksperymentalną sekcję pracy.

#### Zbieranie danych — realistyczne, bez poświęcania miesięcy

1. **Własne zbieranie (primary data) — 1–2 dni:**
   - Spacer z kartą po kampusie/mieście → beacony z dziesiątek AP
   - Etykietowanie: OUI (pierwsze 3 bajty MAC) identyfikuje producenta, ręczna weryfikacja wybranych (podejdź, przeczytaj model z naklejki)
   - Hostapd lab: 3–5 konfiguracji (WPA2/WPA3, z/bez 802.11n/ac, z/bez WMM)

2. **Publiczne datasety:**
   - Wireshark sample captures (wiki.wireshark.org/SampleCaptures)
   - Pcapy z konferencji security i CTF-ów

3. **Syntetyczne augmentacje:**
   - Permutacje konfiguracji hostapd → warianty IE bez stawiania fizycznego AP

#### Cechy (features)

```
Wektor cech z beacon frame (~40–80 wymiarów):
- IE sequence: bag-of-IEs (binary: czy IE typu X jest obecny)
- IE count
- Supported rates vector
- HT capabilities flags (16 bitów)
- VHT capabilities flags (32 bity, jeśli obecne)
- RSN cipher count + typy
- RSN AKM count + typy
- Extended capabilities bitfield (długość + klucz. bity)
- Vendor IE count + OUI set
- WMM/WME present (bool)
- Country IE present (bool)
- Beacon interval
- Capability Info flags (16 bitów)
```

#### Model i ewaluacja

**Primary:** Random Forest / XGBoost — dobrze na mieszanych cechach, daje feature importance, szybki inference.

**Porównanie w pracy (materiał eksperymentalny):**
- Random Forest vs XGBoost vs prosty NN (2–3 warstwy dense)
- Rule-based lookup (ręczne reguły na IE sequence) vs ML
- Pytanie: czy ML daje lepszą klasyfikację niż proste reguły? Jeśli tak — o ile? Jeśli nie — ML jest overengineering i to też jest wartościowy wynik.

**Kluczowa metryka bezpieczeństwa:** Czy hostapd jest kiedykolwiek klasyfikowany jako enterprise AP? False negative rate na klasie "hostapd" = ryzyko przegapienia evil twin.

**Deliverable:** Wytrenowany model z raportem, zintegrowany z Modułem 3 jako opcjonalna warstwa obok clusteringu.

---

### ETAP 4: Dashboard i API (tygodnie 6–7)

**Cel:** Prosty, funkcjonalny interfejs do monitorowania sieci i przeglądania alertów. Nie magnum opus — narzędzie bezpieczeństwa, czytelne i użyteczne.

#### Backend API (FastAPI)

```
Endpointy:
GET  /api/aps                      — lista AP z fingerprints i statusem
GET  /api/aps/{bssid}              — szczegóły AP + historia cech
GET  /api/aps/{bssid}/timeline     — timeline zdarzeń dla AP
GET  /api/alerts                   — lista alertów (filtrowanie, paginacja)
GET  /api/alerts/{id}              — szczegóły alertu z evidence i explanation
GET  /api/stats                    — statystyki (uptime, pakiety/s, AP count)
GET  /api/deauth/stats             — statystyki deauth per kanał
WS   /ws/live                     — WebSocket stream (alerty, nowe AP, updates)

POST /api/aps/{bssid}/acknowledge  — potwierdź alert / oznacz jako OK
POST /api/config                   — zmień parametry (thresholds, wagi modułów)
POST /api/verify/{bssid}           — uruchom Active Verification na żądanie
```

#### Frontend Dashboard (React)

**Widoki (minimum viable):**

1. **Overview** — tabela AP: SSID, BSSID, kanał, RSSI, status (zielony/żółty/czerwony), firmware guess, ostatni alert
2. **AP Detail** — wykresy clock skew/RSSI/seq over time, IE fingerprint, historia alertów, evidence
3. **Alerts** — timeline z explanation, contributing modules, severity
4. **Deauth Monitor** — ramki deauth/s per kanał (bar chart lub heatmap)

**Technologia:** React + shadcn/ui + Recharts. Nie więcej. Prostota > elegancja.

**Deliverable:** Działający dashboard połączony z engine przez WebSocket.

---

### ETAP 5: Eksperymenty i Ewaluacja (tygodnie 7–10)

**Cel:** Systematyczna ewaluacja — serce pracy inżynierskiej. Każdy eksperyment odpowiada na konkretne pytanie badawcze.

---

#### Eksperyment 1: Unikatowość i stabilność Clock Skew

**Pytanie:** Czy clock skew jest wystarczająco unikalny i stabilny do identyfikacji urządzeń?

**Setup:**
- 5–10 różnych AP (różny sprzęt/vendor) w kontrolowanym środowisku
- Każdy: 30 minut beaconów → clock skew
- Powtórzenie: po 1h, po 24h, po 7 dniach → stabilność temporalna
- Z różnych pozycji odbiorcy (3 lokalizacje) → wpływ odległości

**Metryki:**
- Unikatowość: |skew_A - skew_B| dla każdej pary urządzeń
- Stabilność: σ(skew) tego samego urządzenia w czasie
- Czas konwergencji: ile beaconów do stabilnego skew (±0.1 ppm)
- Wpływ pozycji: czy skew zmienia się z lokalizacją odbiorcy (nie powinien)

**Oczekiwane wyniki:** clock skew różni się o 1–20 ppm między urządzeniami, stabilność ±0.1 ppm na przestrzeni godzin, konwergencja po 50–200 beaconach.

---

#### Eksperyment 2: Evil Twin Detection Rate

**Pytanie:** Czy system wykrywa evil twin, z jakim opóźnieniem i który moduł jest najskuteczniejszy?

**Scenariusze testowe:**

| ID | Opis | Trudność | Oczekiwany moduł detekcji |
|---|---|---|---|
| S1 | ET z innym MAC (tylko SSID) | Trywialne | Moduł 3 (environment) |
| S2 | ET ze sklonowanym MAC + SSID | Standardowe | Moduł 1 (clock skew) |
| S3 | S2 + ten sam kanał | Trudne | Moduł 1 (clock skew + seq) |
| S4 | S2 + deauth flood przed włączeniem ET | Standardowe | Moduł 2 + 1 (korelacja) |
| S5 | S2 + ten sam model sprzętu | Bardzo trudne | Moduł 1 (clock skew jedyny sygnał) |
| S6 | ET na hostapd vs enterprise AP | Standardowe | Moduł 3 (firmware mismatch) |

**Metryki per scenariusz:**
- Detection rate (ile razy z N prób system wykrywa)
- Time to detect (sekundy od uruchomienia ET do alertu)
- Który moduł/moduły alertują
- Confidence/severity alertu
- False positive rate w tym samym okresie

**Setup:** Laptop z drugą kartą Alfa + hostapd + dnsmasq. Opcjonalnie RPi jako drugi ET.

---

#### Eksperyment 3: Ablation Study — wartość każdego modułu

**Pytanie:** Ile wnosi każdy moduł? Co się stanie jak go wyłączymy?

**Metoda:**
- Uruchom pełen system (4 moduły) → baseline detection rate + FP rate
- Wyłączaj moduły po kolei:
  - Bez Modułu 1 (no clock skew) → jak spada detection?
  - Bez Modułu 2 (no deauth) → jak spada detection?
  - Bez Modułu 3 (no environment) → jak spada detection?
  - Bez Modułu 4 (no active) → jak spada detection?
  - Tylko Moduł 1 → jak działa sam clock skew?
  - Tylko Moduł 3 → jak działa sam clustering?
- Tabela: konfiguracja → detection rate × FP rate

**Dlaczego to jest wartościowe:** Ablation study jest standardem w pracach naukowych z ML/security. Pokazuje że system jest przemyślany i każdy komponent ma uzasadnienie. Jeśli okaże się że jeden moduł wystarczy — to też jest wartościowy wynik (Occam's razor).

---

#### Eksperyment 4: Klasyfikator Firmware (jeśli zaimplementowany)

**Pytanie:** Z jaką dokładnością model rozróżnia firmware?

**Metryki:** Accuracy, Precision, Recall, F1 per-class, confusion matrix, 5-fold CV, feature importance.

**Porównanie:** Random Forest vs XGBoost vs rule-based lookup. Kluczowe pytanie: czy ML jest wart złożoności vs proste reguły?

---

#### Eksperyment 5: False Positive Analysis

**Pytanie:** Jak często system alertuje bez powodu w normalnych warunkach?

**Scenariusze:**
- 24h monitoringu w środowisku domowym (kilka AP, zero ataków) → ile alertów?
- 24h monitoringu na kampusie (dziesiątki AP, roaming, restarty) → ile alertów?
- Symulacja restartu AP → czy system rozróżnia restart od podmiany?
- Nowy AP pojawia się w zasięgu → jaki alert i severity?
- Roaming klienta między AP z tym samym SSID → czy system poprawnie obsługuje?

---

#### Eksperyment 6: Porównanie z istniejącymi narzędziami

**Tabela porównawcza:**

| Cecha | WiGuard | waidps | EvilAP_Defender | airodump-ng |
|---|---|---|---|---|
| Clock skew fingerprint | ✓ | ✗ | ✗ | ✗ |
| IE structure fingerprint | ✓ | Częściowo | ✗ | ✗ |
| Deauth flood detection | ✓ | ✓ | ✗ | ✗ (manual) |
| Environment clustering | ✓ | ✗ | ✗ | ✗ |
| Active verification | ✓ | ✗ | ✗ | ✗ |
| ML firmware classifier | Opcja | ✗ | ✗ | ✗ |
| Multi-module correlation | ✓ | ✗ | ✗ | N/A |
| Zero-config | ✓ | ✗ (whitelist) | ✗ (whitelist) | N/A |
| Explainable alerts | ✓ | ✗ | ✗ | N/A |
| Real-time dashboard | ✓ | CLI | CLI | CLI |
| Detection rate (ET S2) | ? | ? | ? | Manual |
| Time to detect | ? | ? | ? | Manual |
| False positive rate | ? | ? | ? | Manual |

Testy: uruchom te same scenariusze S1–S6 na WiGuard i na dostępnych narzędziach. Porównaj detection rate i FP rate.

---

### ETAP 6: Pisanie Pracy (tygodnie 9–14)

#### Proponowana struktura pracy (~50–65 stron)

1. **Wstęp** (~3 strony)
   - Kontekst zagrożenia evil twin w sieciach WiFi
   - Cel pracy, teza, zakres
   - Struktura dokumentu

2. **Analiza problemu i przegląd literatury** (~10 stron)
   - Techniczny opis ataku evil twin (warianty, przebieg, narzędzia atakującego)
   - Taksonomia ataków (pasywny MitM, credential harvesting, captive portal, karma attack)
   - Przegląd istniejących metod detekcji:
     - Metody oparte na whitelistach (SSID/BSSID)
     - Clock skew fingerprinting (Jana & Kasera, Bratus et al.)
     - Fingerprinting radiowy (PHY layer)
     - Systemy WIDS/WIPS enterprise
   - Istniejące narzędzia open-source i ich ograniczenia
   - Luka badawcza: brak zintegrowanego multi-warstwowego podejścia zero-config z korelacją sygnałów

3. **Projekt systemu WiGuard** (~12 stron)
   - Architektura systemu (diagramy, przepływ danych)
   - Feature Extraction Pipeline
   - Moduł 1: AP Identity Verification (teoria + algorytmy)
   - Moduł 2: Deauth Storm Detection
   - Moduł 3: Environment Anomaly Detection
   - Moduł 4: Active Verification
   - Alert Correlation Engine
   - Decyzje projektowe i ich uzasadnienie
   - Analiza ograniczeń projektowych

4. **Implementacja** (~10 stron)
   - Stos technologiczny i uzasadnienie wyboru
   - Kluczowe algorytmy (clock skew estimation, IE hashing, CUSUM)
   - Architektura kodu (moduły, interfejsy, przepływ danych)
   - Dashboard i API
   - Trudności implementacyjne i rozwiązania
   - Testy (jednostkowe, integracyjne, pcap replay)

5. **Eksperymenty i wyniki** (~15 stron)
   - Metodologia i środowisko testowe
   - Eksperyment 1: Clock skew (wykresy, tabele)
   - Eksperyment 2: Detection rate per scenariusz
   - Eksperyment 3: Ablation study
   - Eksperyment 4: ML classifier (jeśli zaimplementowany)
   - Eksperyment 5: False positive analysis
   - Eksperyment 6: Porównanie z innymi narzędziami
   - Dyskusja wyników

6. **Dyskusja i ograniczenia** (~3 strony)
   - Ograniczenia systemu (zaawansowany atakujący, PMF, heterogeniczne środowiska)
   - Potencjalne obejścia i mitygacje
   - Kierunki rozwoju (multi-sensor, SDR, integracja z SIEM, lokalizacja)

7. **Podsumowanie** (~2 strony)

---

## 3. Ryzyka i Mitygacje

| Ryzyko | Wpływ | Mitygacja |
|---|---|---|
| Karta Alfa nie działa w monitor mode / brak TSF | Blokujące | Test jako pierwsza rzecz w Etapie 0. Backup: inna karta (TP-Link TL-WN722N v1, chipset Atheros) |
| Clock skew nie rozróżnia urządzeń w praktyce | Wysoki | Pozostają Moduły 2–4. Clock skew staje się dodatkową cechą. W pracy: uczciwy opis wyniku |
| Za mało danych do ML classifiera | Średni | ML jest opcjonalny — clustering + rule-based lookup jako fallback |
| Evil twin ze skopiowanymi IE | Średni | Clock skew nadal wykrywa. W pracy: opisać jako granicę systemu |
| Zbyt dużo false positives | Średni | Kalibracja thresholdów, korelacja modułów redukuje FP, grace period |
| Brak drugiej karty do Active Verification | Niski | Moduł 4 jako opcjonalny. Tania karta USB (~30 zł) jako backup |
| Brak czasu na pełny dashboard | Niski | CLI output + prosty web UI. Wykresy jako nice-to-have |

---

## 4. Stos Technologiczny

**Sensor / Backend:**
- Python 3.11+
- Scapy — parsowanie 802.11
- NumPy / SciPy — regresja, statystyka, CUSUM
- scikit-learn / XGBoost — opcjonalny klasyfikator firmware
- HDBSCAN — clustering (Moduł 3)
- FastAPI — REST API + WebSocket
- SQLite — historia alertów i cech (lekkie, zero konfiguracji)

**Frontend:**
- React + TypeScript
- shadcn/ui — komponenty
- Recharts — wykresy
- WebSocket client

**Infrastruktura:**
- Linux (dedykowany system lub VM)
- Karta Alfa (monitor mode) — sensor
- Opcjonalnie: druga karta WiFi (active verification)
- Opcjonalnie: Raspberry Pi jako sensor
- Git + GitHub

**Testowanie:**
- pytest — testy jednostkowe i integracyjne
- pcap replay — odtwarzanie zarejestrowanych sesji

---

## 5. Timeline — Realistyczny

```
Tydzień 1:       [ETAP 0] Setup, monitor mode, basic capture, weryfikacja TSF
Tygodnie 2–3:    [ETAP 1] Feature extraction (clock skew, IE, RSSI, seq, deauth counting)
Tygodnie 3–5:    [ETAP 2] Detection engine (4 moduły + correlation engine)
Tygodnie 5–6:    [ETAP 3] ML classifier (opcjonalnie, jeśli czas pozwala)
Tygodnie 6–7:    [ETAP 4] Dashboard + API
Tygodnie 7–10:   [ETAP 5] Eksperymenty (6 eksperymentów)
Tygodnie 9–14:   [ETAP 6] Pisanie pracy (równolegle z poprawkami systemu)
```

Całość: ~3.5 miesiące intensywnej pracy, ~5–6 miesięcy w realistycznym tempie.

---

## 6. Minimalne MVP vs Pełny System

**MVP (wystarczający na obronę):**
- Moduł 1 (clock skew + IE fingerprint + identity verification)
- Moduł 2 (deauth storm detection)
- CLI output z alertami i explanation
- Eksperymenty 1, 2, 5 (clock skew, detection rate, FP)
- Prosty dashboard (tabela + alerty)

**Pełny system (imponujący):**
- Wszystkie 4 moduły + correlation engine
- ML classifier z ewaluacją
- React dashboard z real-time
- 6 eksperymentów + ablation study
- Porównanie z istniejącymi narzędziami
- Active Verification
- Procedura testowa deauth (Dodatek A)

**Zalecenie:** Buduj od MVP, rozszerzaj. Moduły 3 i 4 dopisujesz jak MVP działa.

---

## Dodatek A: Procedura Testowa Deauth (Opcjonalna — Narzędzie Ofensywne)

### Cel
Zintegrowany moduł pozwalający administratorowi sieci przetestować odporność firmowej infrastruktury WiFi na atak deauthentication flood. Użytkownik wskazuje AP (po BSSID lub SSID) i WiGuard przeprowadza kontrolowany test, raportując jak sieć i podłączeni klienci reagują.

### Kontekst i uzasadnienie
Atak deauthentication jest standardowym prekursorem evil twin. Nowoczesne sieci powinny być odporne dzięki 802.11w (Protected Management Frames / PMF). Ale wiele sieci firmowych nadal go nie wdraża. Ten moduł pozwala zweryfikować:
- Czy sieć jest podatna na deauth flood?
- Czy klienci się rozłączają? Jak szybko? Ile z nich?
- Czy ponowne połączenie następuje automatycznie i z jakim opóźnieniem?
- Czy sieć ma włączone PMF (i czy działa)?

### Ważne zastrzeżenie prawne
Wysyłanie ramek deauthentication do sieci, której nie administrujemy, jest **nielegalne** w większości jurysdykcji (w UE: Dyrektywa o atakach na systemy informacyjne, w PL: art. 267–269 KK). System musi wyraźnie informować użytkownika i wymagać potwierdzenia:
```
⚠  OSTRZEŻENIE: Procedura testowa deauth wysyła ramki deauthentication
   do wskazanego AP. Jest to technika ofensywna, której użycie bez
   autoryzacji administratora sieci jest nielegalne.
   
   Potwierdź że masz autoryzację do testowania tej sieci: [TAK/NIE]
   Wpisz BSSID docelowego AP: ___
   Czas trwania testu (sekundy, max 60): ___
```

### Implementacja

#### Faza 1: Rekonesans (przed testem)
```
1. Zidentyfikuj docelowy AP (BSSID, SSID, kanał)
2. Zbierz baseline:
   - Lista klientów połączonych z AP (z ramek data/management)
   - Aktualny fingerprint AP (clock skew, IE, RSSI)
   - Aktualny deauth rate (powinien być ~0)
   - Sprawdź czy AP rozgłasza PMF capability (RSN IE, bit MFPC/MFPR)
3. Raport pre-test:
   "AP: BSSID XX:XX, SSID 'FirmNetwork', kanał 6
    Klienci: 12 podłączonych
    PMF: nie wykryto (sieć potencjalnie podatna)
    Gotowy do testu."
```

#### Faza 2: Test deauth (kontrolowany)
```
Parametry konfigurowane przez użytkownika:
  - target_bssid: BSSID docelowego AP
  - mode: "broadcast" | "targeted"
    - broadcast: deauth do FF:FF:FF:FF:FF:FF (odłącza wszystkich)
    - targeted: deauth do konkretnego klienta (mniej destrukcyjne)
  - rate: ramki/s (np. 10, 50, 100)
  - duration: sekundy (max 60, domyślnie 10)
  - intensity: "low" (10 ramek/s) | "medium" (50/s) | "high" (100/s)

Wykonanie:
1. Ustaw kartę na kanał docelowego AP
2. Konstruuj ramki Deauthentication:
   - source: BSSID docelowego AP (spoofing)
   - destination: broadcast lub konkretny klient
   - reason code: 7 (Class 3 frame from nonassociated STA)
3. Wysyłaj z zadanym rate przez zadany duration
4. Jednocześnie monitoruj (na drugiej karcie lub naprzemiennie):
   - Klienci: ilu się rozłączyło?
   - Czy AP odpowiada normalnie? (beacony lecą?)
   - Czy klienci próbują się ponownie połączyć?
   - Czy ramki deauth są faktycznie skuteczne? (PMF je blokuje?)
```

#### Faza 3: Analiza post-test
```
Raport z testu:
  ┌─────────────────────────────────────────────────────┐
  │  DEAUTH RESILIENCE TEST REPORT                      │
  │                                                     │
  │  Target: AA:BB:CC:DD:EE:FF (FirmNetwork)            │
  │  Test duration: 10 seconds @ 50 frames/s            │
  │  Total deauth frames sent: 500                      │
  │                                                     │
  │  PMF Status: NOT ENABLED                            │
  │                                                     │
  │  Results:                                           │
  │  ├─ Clients before test: 12                         │
  │  ├─ Clients disconnected: 9 (75%)                   │
  │  ├─ Time to first disconnect: 0.3s                  │
  │  ├─ Clients reconnected within 30s: 7               │
  │  ├─ Clients still disconnected after 60s: 2         │
  │  └─ AP beacon continuity: maintained                │
  │                                                     │
  │  VERDICT: VULNERABLE                                │
  │                                                     │
  │  Recommendations:                                   │
  │  1. Enable 802.11w (PMF) on all APs                 │
  │  2. Configure PMF as Required (not Optional)        │
  │  3. Ensure all client devices support PMF           │
  │  4. Consider deploying WiGuard for continuous       │
  │     monitoring of deauth anomalies                  │
  └─────────────────────────────────────────────────────┘
```

### Tryby testu

**Quick Test (domyślny):**
- 10 sekund, 50 frames/s, broadcast
- Odpowiada na: "czy sieć jest podatna?"

**Progressive Test:**
- Seria testów z rosnącym rate: 10/s → 25/s → 50/s → 100/s
- Każdy etap: 5 sekund, 10 sekund przerwy na obserwację
- Odpowiada na: "przy jakim natężeniu sieć zaczyna się degradować?"

**Targeted Client Test:**
- Deauth do jednego wybranego klienta
- Mniej destrukcyjne, precyzyjniejsze
- Odpowiada na: "czy dany klient jest odporny na deauth?"

**PMF Verification Test:**
- Wysyła deauth i sprawdza czy klienci z PMF ignorują je
- Weryfikuje czy konfiguracja PMF faktycznie działa
- Odpowiada na: "czy wdrożenie PMF jest skuteczne?"

### Integracja z WiGuard

Moduł testowy korzysta z istniejącej infrastruktury:
- **Capture Engine** — do monitorowania efektu testu (klienci, beacony)
- **AP State Manager** — baseline fingerprint AP przed i po teście
- **Deauth Storm Detection (Moduł 2)** — weryfikacja że własny moduł detekcji widzi test jako atak (self-test systemu detekcji)
- **Dashboard** — wizualizacja wyników testu w UI

Ten ostatni punkt jest szczególnie wartościowy: uruchomienie procedury testowej deauth jest jednocześnie testem Modułu 2. Jeśli WiGuard nie wykryje własnego deauth flood — masz bug do naprawienia.

### Realne problemy
- **Prawne:** Użycie bez autoryzacji = przestępstwo. System musi to jasno komunikować i logować kto, kiedy i na jakiej sieci uruchomił test.
- **Wpływ na produkcję:** Nawet krótki deauth test rozłącza klientów. Testować poza godzinami pracy lub na izolowanym AP.
- **Wymagania sprzętowe:** Karta musi obsługiwać injection mode (nie tylko monitor). Alfa z chipsetem RTL8812AU lub Atheros AR9271 obsługuje. Sprawdzić: `aireplay-ng --test wlan0mon`.
- **PMF false confidence:** Nawet z PMF, atakujący może użyć innych technik (np. CSA — Channel Switch Announcement spoofing, albo Rogue AP without deauth). Test deauth sprawdza tylko jeden wektor ataku.
