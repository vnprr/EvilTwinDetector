# Prompt dla Claude — pełny audyt WiGuard na realnym kodzie (26.10.2026)

Jesteś niezależnym audytorem technicznym systemu **WiGuard** (`vnprr/EvilTwinDetector`). Zlecenie: **dokładnie przeskanuj kod, przeanalizuj algorytmy, uruchom testy i potwierdź rzeczywisty stan implementacji**. Nie zamieniaj audytu w szeroki refaktor ani implementację nowych funkcji.

## Kontrakt wykonania

1. Zacznij od `git status --short --branch`, `git remote -v`, `git branch -avv`, `git log --all --decorate --oneline -n 40`; zanotuj HEAD, OS, kernel, wersje Python/Node, interfejsy/sterowniki, dostępność sprzętu.
2. Aktualny plan i zakres z repo: `docs/PROJECT-ROADMAP.md` oraz `docs/THESIS-PLAN.md`. Stary `wiguard-plan-v2.md` to dokument historyczny, może zawierać planowane funkcjonalności opisane w trybie dokonanym.
3. Na zdalnym GitHubie w dniu 26.10.2026 widoczny był tylko `main`, a bazowy kod kończył się commit `609b01e` (07.05.2026). **Sprawdź lokalne `reflog`, `stash`, nieosiągalne commity, worktrees i ewentualny dawny branch `claude/*`**. Jeśli odkryjesz implementację live disconnect/deauth lub naprawy, zrób osobny diff, ocenę jakości/testów oraz dokumentację. **Nie scalaj** niezweryfikowanego kodu. Nie rób `git gc` ani nie usuwaj odzyskiwalnych commitów.
4. Pracuj tylko w repo; nie używaj GitHub Actions do długich testów. Wykonuj lokalne, powtarzalne polecenia. Nie uruchamiaj niekontrolowanych działań radiowych, rozłączania, injection, skanowania cudzej sieci ani testów zakłócających. Eksperymenty RF uruchamiaj wyłącznie na sprzęcie laboratoryjnym i po potwierdzeniu autoryzacji oraz zakresu.
5. **Najpierw raport bez zmian produkcyjnego kodu**. Możesz wygenerować lokalne raporty/logi; nie committuj poprawek ani nie dokładaj modułów bez osobnej decyzji. Jeśli test nie może się wykonać, zgłoś `NOT RUN` i konkretny powód; nigdy nie wpisuj PASS z pamięci, logu maja lub na podstawie oczekiwań.
6. Nie proponuj rozbudowanej architektury frameworkowej; szukaj najprostszych, spójnych, modułowych napraw. Priorytetem są niezawodność, prawdziwe wyniki i ukończenie pracy inżynierskiej.
7. Po każdym dużym etapie weryfikacji zapisz podsumowanie: **co potwierdzone, co obalone, co niewykonalne w tym środowisku**.

## Etap A — mapa prawdziwej implementacji

Przejrzyj co najmniej:
- `wiguard/src/wiguard/capture/*` — obsługa adaptera, monitor mode, channel hop, restore, obsługa błędów.
- `features/*` oraz `state/*` — parser, IE, RadioTap/TSF, clock skew, RSSI, timing, sequence, agregacja i pamięć.
- `detection/*` — identity, baselines, duplicate-BSSID residual clustering, deauth storm, environment.
- `correlation/*` — logika score, cooldown, dedup, związki sygnałów, classification.
- `runtime/*` — sensor, SQLite, procesy długotrwałe, restart, recovery.
- `api/*` — FastAPI, health/status, AP, alert, WS, kontrakty, błędy, security.
- `dashboard/*` — React/TS, odczyt API, terminal reconnect, UX, brak danych, loading, stale records, błędy.
- `evaluation/*`, `experiments/*`, `tests/*`, `docs/*`, `config.yaml`, `pyproject.toml`, `README.md`.
- `active/*`, `ml/*` — czy są realne moduły, czy same puste `__init__.py`.

Macierz: **IMPLEMENTED / PARTIAL / MISSING / BROKEN / UNVERIFIED**. Do każdego twierdzenia podaj **ścieżka:linia** plus test lub eksperyment. Nie nazywaj fake/synthetic deauth generatora działającym modułem rozłączania.

## Etap B — uruchomienie rzeczywistych testów

Pracuj w izolowanym virtualenv, wykonuj polecenia zgodne z repo i loguj dokładne wersje zależności. Nie zakładaj istnienia plików, których nie ma.

Przykładowe bramki bazowe (dostosuj tylko jeśli instrukcje repo wymagają):

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
wiguard-generate-fixtures tests/pcap_fixtures/synthetic
wiguard-evaluate-fixtures tests/pcap_fixtures/synthetic/manifest.json
cd dashboard
npm ci            # jeśli istnieje aktualny package-lock.json; inaczej wyjaśnij wybór
npm run typecheck
npm run build
```

Następnie:
- Bezpieczny smoke API na tymczasowej bazie: `GET /api/health`, `/api/aps`, `/api/alerts`, `/api/events`, `/api/stats`, przykładowy `WS /ws/live`.
- Uruchom dashboard z demo DB, w prawdziwej przeglądarce sprawdź listę AP, szczegóły, alerty, timeline, przejścia, awarię/odłączenie API, pustą bazę. Nie zaliczaj samego `vite build` jako testu UI.
- Unit i integracyjne testy ze sztucznymi danymi są **oddzielne** od live RF tests. Pokaż liczby PASS/FAIL/ERROR/SKIP dla każdej bramki.
- Jeśli prawdziwy adapter jest dostępny, sprawdź **tylko pasywny** nasłuch i recovery, bez zakłócania aktywnego połączenia internetowego. Przed ingerencją w interfejs potwierdź, że to adapter laboratoryjny. Jeśli brak adaptera — status `NOT RUN`.

## Etap C — analiza correctness, nie tylko zliczanie testów

Dla każdego podejrzanego problemu odtwórz go małym testem/regresją bez zmieniania funkcjonalności (możesz tworzyć tymczasowe skrypty testowe):
- IE: dynamic fields, reorder, vendor OUIs, brak IE, malformed/truncated, security downgrade, WPA2/WPA3/PMF.
- Clock skew: jednostki TSF i lokalnego czasu, regresja, offset i slope, wrap/reset, dropout, hopping, monotonic vs wall clock, niewystarczająca liczba próbek, podatność na outliers, aktualizacja baseline.
- Duplicate BSSID: jeden AP z jitterem, realne dwa profile, nierówne próbki, sekwencja interleaving, RSSI split, zachowanie przy channel hopping; potwierdzenie z niezależnego sygnału.
- Deauth: broadcast vs unicast, false attribution do BSSID, błędne źródła, burst/okno, reset, wygaśnięcie starej próbki, „0 deauth” przy ataku.
- Environment: heterogeniczny same-SSID z legalnymi AP, brak peers, większość, wahania konfiguracji i firmware update.
- Correlation: nie dodawać wag zależnych sygnałów jak niezależnych; source provenance, bounded score, progi `info/suspicious/evil_twin`, cooldown, powtarzalność, unikalna tożsamość alertu. `score` **nie jest automatycznie prawdopodobieństwem**.
- Config: sprawdź, czy **zmiana progu w `config.yaml` zmienia działanie**; nie wystarcza istnienie YAML. Ustal źródło prawdy dla każdej wartości.
- Runtime/API: shutdown, flush, race conditions, SQLite error/restart, path traversal, CORS, brak uprawnień do pliku, błędy danych, nieograniczona retencja, ws polling/reconnect.
- Frontend: stan przy stale/offline, brak silent failures, brak udawanej akcji sukcesu, klawiatura i responsywność, czytelna hierarchia UI. Tylko rzeczywisty browser smoke, nie nieograniczony Playwright crawl.

## Etap D — weryfikacja potrzeby Red i Blue

**Blue:** co istnieje, czego brakuje do obrony pracy? Pełny evidence drill-down, sensor health, konfiguracja baseline, eksport surowych danych i alertów, offline replay, synchronizacja czasu, czytelność score.

**Red:** czy cokolwiek jest faktycznie wdrożone? Odróżnij:
- generowanie syntetycznych PCAP z Dot11Deauth,
- detektor pasywny deauth,
- sterowanie własnym AP przez oficjalne API,
- laboratorium imitacji SSID/BSSID,
- realne transmisje testowe,
- panel scenariuszy,
- ground truth i automatyczny evaluator.

Dla braków przygotuj *minimalny* plan: prawdziwy test na własnym AP, odrębne radio, API o wąskim zakresie funkcji, domyślny dry-run i fail-closed. Bez tworzenia otwartego „disconnection toolkit” ani wykonywania live deauth na otoczeniu. Moduł aktywnego rozłączania jest **opcjonalny**, tylko jeśli pomaga w eksperymentach; najpierw można sprawdzić reakcję Blue na bezpieczne, kontrolowane scenariusze.

## Etap E — ocena gotowości do pracy inżynierskiej

Powiąż repo z `docs/THESIS-PLAN.md`. Oceń, czy system może wykazać:
1. stabilność cech z wielu sesji i sprzętów;
2. wykrywalność S1–S6 i czas do alertu;
3. false positive i false negative, w tym benign controls;
4. ablation każdej klasy sygnału;
5. zgodność capture na min. dwóch chipsetach oraz różnych AP;
6. reproducibility i ground truth Red bez przecieku do Blue.

Zaznacz, jakich **danych / sprzętu / modyfikacji kodu** brakuje do każdego doświadczenia. Nie myl benchmarku Scapy 5/5 z naukowo udowodnioną detection rate.

## Rezultat — dokładny raport (nie ogólna opinia)

Przygotuj `docs/audits/WIGUARD-AUDIT-2026-10-26.md` w lokalnym drzewie roboczym (bez commitu, dopóki nie będziesz miał polecenia):
1. stan HEAD i środowiska, odzyskiwalne branche/reflog;
2. macierz implementacji z odnośnikami do kodu i dowodami;
3. tabela bramek testowych z poleceniami, wynikami i liczbą testów;
4. **lista błędów P0/P1/P2**: objaw, root cause, ścieżka:linia, sposób odtworzenia, konsekwencja, najprostsza naprawa, test regresyjny;
5. architektura: co jest nadmiernie złożone, zdublowane lub pozorne; propozycja minimalnego uproszczenia;
6. lista braków dla Blue i Red z priorytetami i kryteriami akceptacji;
7. gotowość do czterech najważniejszych eksperymentów;
8. zwięzły plan napraw w małych porcjach — najpierw P0, potem P1, P2, P3;
9. jednoznaczne **GO/NO-GO** dla rozpoczęcia badań, z uzasadnieniem.

**Zakaz pustych ocen:** „wygląda dobrze”, „testy są zielone”, „działa” bez wyników nie mają wartości. Jeżeli nie masz dostępu do adaptera lub hosta z GUI, napisz `NOT RUN`, czego brakuje i jakie komendy należy wykonać na maszynie laboratoryjnej.

Na końcu wyświetl w czacie **maksymalnie 12 konkretnych najważniejszych wniosków**, link do lokalnego raportu i propozycję pierwszego kroku. **STOP po audycie. Nie implementuj nowych funkcji ani nie scalaj gałęzi automatycznie.**
