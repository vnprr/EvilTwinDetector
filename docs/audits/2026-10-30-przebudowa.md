# Przegląd kodu i przebudowa — 30.10.2026

Cały kod (Python i dashboard) został przeczytany od początku do końca. Poniżej:
co było źle, dlaczego to miało znaczenie i co zrobiono. Szczegóły nowej
architektury: [ARCHITECTURE.md](../ARCHITECTURE.md).

## Błędy logiki (wpływały na wyniki detekcji)

| # | Problem | Skutek | Naprawa |
|---|---|---|---|
| 1 | Weryfikacja tożsamości porównywała tylko **znane** BSSID z ich profilem. | Klasyczny Evil Twin (nowy BSSID, ten sam SSID, jeden legalny AP) był niewidoczny dla identity; environment wymaga ≥ 3 AP. | Sygnał `unknown_bssid_for_trusted_ssid`. |
| 2 | Korelacja grupowała wyłącznie po BSSID. | Deauth jest fałszowany z BSSID prawdziwego AP, więc nigdy nie wzmacniał alertu bliźniaka; reguła premii {deauth, environment} była praktycznie martwa. | Powiązanie burzy deauth z bliźniakiem po SSID (`linked_from`). |
| 3 | Wynik: suma wag sygnałów w module, mnożnik `1 + 0,35·(n−1)` i ręczna tabela premii; cztery różne tabele wag ważności. | Podwójne liczenie tej samej przyczyny, brak uzasadnienia liczb. | Noisy-OR, najsilniejszy sygnał w module, jedna skala ważności, reguły projektowe pilnowane testem. |
| 4 | Duplikat BSSID: „potwierdzenie” różnicą wyrazu wolnego było tautologiczne (wynika z samej luki rezyduów). | Restart AP mógł wyglądać jak bliźniak. | Kryterium separacji pasm + wymóg przeplatania w czasie; nowy sygnał konfliktu kanałów. |
| 5 | Sensor dopisywał wszystkie alerty deauth z okna 300 s do bazy przy każdym zapisie (co 5 s), a detektor tworzył alert z każdej ramki. | Te same zdarzenia zapisane dziesiątki razy, rozrost bazy. | Epizody burz; zdarzenia zapisywane tylko przy zmianie. |
| 6 | Alert nigdy się nie zamykał, nowy zestaw sygnałów tworzył nowy wiersz, stary dowód (AP dawno zniknął) liczył się bez końca. | Panel pokazywał nieaktualne zagrożenia. | Incydent na AP: otwarcie, eskalacja, zamknięcie; okno dowodów. |
| 7 | API „tylko do odczytu” przy każdym żądaniu wykonywało `CREATE`/`INSERT` (inicjalizacja schematu) i tworzyło plik bazy. | Zapisy konkurujące z sensorem, deklaracja niezgodna z prawdą. | Połączenie SQLite `mode=ro`. |
| 8 | Fixtures syntetyczne: nagłówek RadioTap bez pól (brak RSSI, kanału, TSFT) i ucięty element RSN; parser oparty na klasach Scapy gubił wszystkie IE po pierwszym nierozpoznanym. | Scenariusz z „RSSI split” nie mógł zadziałać; fingerprint z prawdziwych beaconów mógł być niepełny. | Własne parsowanie TLV; nowy generator (10 scenariuszy, w tym kontrole negatywne). |
| 9 | Ewaluator zamieniał `info` na `suspicious` i liczył dowolny surowy alert jako `suspicious`. | Zawyżona wykrywalność. | Werdykt AP docelowego, macierz pomyłek 4×4. |
| 10 | Czas: na żywo `CLOCK_MONOTONIC_RAW` odczytywany w callbacku (z opóźnieniem przetwarzania), offline znacznik z pcap. | Różne zegary w trybie live i offline. | Wszędzie znacznik przechwycenia z jądra (`packet.time`). |
| 11 | Estymator skew mieszał próbki sprzed i po restarcie AP. | Fałszywe „zmiany zegara”. | Reset estymatora przy spadku TSF. |
| 12 | Sekwencje: heurystyka „zawinięcie, gdy poprzedni ≥ 3500 i bieżący ≤ 600”. | Błędna klasyfikacja dużych przeskoków. | Arytmetyka numerów seryjnych (RFC 1982). |
| 13 | Oś czasu w API zwracała **najstarsze** 100 wpisów. | Długo działający sensor pokazywał zdarzenia sprzed wielu godzin. | Najnowsze wpisy lub wpisy po `after_id`. |
| 14 | `scapy.sniff` połykał Ctrl+C. | Pętla kanałów działała dalej. | `chainCC=True`, przerwanie kończy przechwytywanie i zostawia wyniki. |
| 15 | Połączenie SQLite tworzone w innym wątku niż używane przez FastAPI (wykryte testem w prawdziwej przeglądarce). | Losowe błędy 500. | Połączenie dopuszczające przekazanie między wątkami + test regresyjny. |

## Struktura i jakość kodu

* Dwa równoległe stany AP (`APState` i `APFeatureState`) i dwa modele ramki; każdy
  pakiet parsowany dwa razy → **jeden parser i jeden profil AP**.
* Trzy kopie potoku detekcji (scan, sensor, analiza pcap) → **`DetectionPipeline`**.
* Trzy identyczne klasy sygnałów, trzy klasy alertów i warstwa konwersji →
  **`Signal` / `DetectionEvent`**.
* Siedem osobnych poleceń → **jedno `wiguard` z podkomendami**.
* Ręczny walidator konfiguracji (~600 linii) → **pydantic** (~230 linii); usunięte
  martwe klucze (`auto_learn`, `forbidden_commands`, waga nieistniejącego modułu
  `active_verification`, zdublowane ścieżki).
* Usunięte puste pakiety `active/`, `ml/`, `utils/`; `requirements.txt` był niezgodny
  z `pyproject.toml` (brak PyYAML); układ `wiguard/src/wiguard` → standardowe `src/wiguard`.
* Testy: `unittest` → **pytest** (112 testów, w tym przypadki, które *nie* mogą
  alarmować), lint i formatowanie **ruff**.
* Dashboard: `App.tsx` (850 linii, 20 stanów w jednym komponencie) → widoki,
  komponenty, hooki i funkcje pomocnicze; dowody prezentowane per detektor, z
  komunikatem i poziomem ważności każdego sygnału.

| | Przed | Po |
|---|---:|---:|
| Kod Pythona (`src`) | 6143 linii | 4457 linii |
| Testy | 1916 linii, 72 testy | 1121 linii, 112 testów |
| Scenariusze syntetyczne | 5 (bez kontroli negatywnych z AP) | 10 (3 kontrole negatywne) |

## Weryfikacja

* `pytest`: 112 zaliczonych, 1 pominięty (wymaga prawdziwego nagrania z karty).
* `ruff check` i `ruff format --check`: bez uwag.
* `wiguard fixtures evaluate`: 10/10, macierz pomyłek diagonalna.
* Dashboard: `npm run build` (typecheck + build) bez błędów; test w Chromium
  (Playwright) wszystkich widoków na bazie z `wiguard replay`: 0 błędów konsoli,
  0 odpowiedzi 500.

## Czego ten przegląd nie zastępuje

Testów na prawdziwym RF. Ani testy, ani scenariusze syntetyczne nie mówią nic o
skuteczności w eterze; to zadanie eksperymentów z [THESIS-PLAN.md](../THESIS-PLAN.md).
Wymagają one ponownego enrollmentu (zmienił się format fingerprintu IE i plik
profili) oraz nowej bazy stanu (schemat 3).

## Runda 2 — modernizacja narzędzi i struktury (30.10.2026)

Zasada: biblioteka wchodzi tylko wtedy, gdy usuwa własny kod albo ręczną duplikację.

| Zmiana | Co zastępuje | Zysk |
|---|---|---|
| **Typer + Rich** (`cli/`) | ~300 linii argparse z parserami-rodzicami i `getattr` | komendy jako typowane funkcje; tabele, kolorowe werdykty, czytelne błędy |
| **logging** (RichHandler) | `print` w sensorze i przechwytywaniu | poziomy logów, `--verbose`, JSON na stdout nie miesza się z logami |
| **pydantic** dla pliku profili i manifestu scenariuszy | ręczne `from_dict`, `_optional`, walidatory | walidacja jednym wywołaniem, ten sam model w API |
| **`StateReader` / `StateWriter`** + `schema.sql` | jedna klasa `RuntimeStore` (500 linii), SQL w stringu, 14 pozycyjnych `?` | API dostaje klasę bez metod zapisu (gwarancja typów + `mode=ro`), parametry nazwane, schemat czytelny jako plik SQL |
| **APIRouter** (`api/routes.py`), typowane modele dowodów | funkcje zagnieżdżone w `create_app`, `dict[str, Any]`, koperty `{count, items}` | pełny dokument OpenAPI, prostsze odpowiedzi (listy) |
| **openapi-typescript + openapi-fetch** | ręcznie przepisany `types.ts` (170 linii) i klient `fetch` | typy dashboardu generowane z API; test i CI pilnują, że są aktualne |
| **TanStack Query** | własny hook `usePolling` | cache, odświeżanie, stany błędów — standardowo |
| **React Router** | widok w `useState` | adres URL dla każdego widoku i alertu (zakładki, przycisk „wstecz”, filtry w URL) |
| **mypy `--strict`**, **hypothesis**, **Biome**, **Vitest** | brak | typy sprawdzane statycznie; testy własnościowe (fuzzing parsera, monotoniczność wyniku); lint i testy dashboardu |
| **uv + `uv.lock`**, **Makefile**, **GitHub Actions** | `pip install -e` bez blokady wersji | odtwarzalne środowisko; `make check` = to samo co CI |

Wynik: `make check` — ruff, mypy (40 plików), Biome, 122 testy pytest (1 pominięty —
wymaga nagrania z karty), 5 testów Vitest; test w Chromium wszystkich widoków i
bezpośrednich linków: 0 błędów konsoli, 0 odpowiedzi 500.
