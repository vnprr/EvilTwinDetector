# WiGuard — plan pracy inżynierskiej i ścieżka dowodowa (26.10.2026)

> Ten dokument uzgadnia **plan pracy dyplomowej** z planem rozwoju systemu. Szczegółowy rękopis pracy powstaje osobno; tutaj utrzymujemy zakres, strukturę, cele i definicje testów. Nie wpisywać hipotetycznych wyników do pracy.

## 1. Tytuł i cel

**Tytuł roboczy:** Projekt i ocena skuteczności systemu wykrywania fałszywych punktów dostępu Wi-Fi.

**Problem inżynierski:** jak wykrywać wybrane formy Evil Twin, w szczególności podszywanie się pod SSID/BSSID, gdy kopiowalne identyfikatory nie pozwalają potwierdzić tożsamości nadajnika.

**Cel:** zaprojektować i zbadać niskokosztowy niezależny detektor, który wykorzystuje kilka cech 802.11, tworzy profil AP, koreluje evidence i wyjaśnia alarmy.

**Nie obiecujemy:** automatycznej, stuprocentowej detekcji, komercyjnego WIPS, „AI od razu”, wykrycia wszystkich ataków ani udowodnionej przewagi nad produktami enterprise. Teza o użyteczności korelacji jest hipotezą do testowania.

**Rola Red:** stanowisko badawcze służące wytwarzaniu kontrolowanych scenariuszy, rejestracji ground truth i ocenie Blue; nie równorzędny temat pracy.

## 2. Pytania i ścieżka odpowiedzi

| Pytanie | Materiał | Odpowiedź w pracy |
|---|---|---|
| P1. Dlaczego potrzebna jest detekcja Evil Twin i jak to rozwiązują inni? | literatura, Kismet, nzyme, Cisco/Meraki/Fortinet/Aruba, segmenty użytkowników | rozdział 1, konkluzja |
| P2. Czy wybrane cechy (IE, TSF/clock skew, RSSI, sequence, deauth) są stabilne/użyteczne? | próby benign, między sesjami/chipsetami | 2, 5.4 i 6.1 |
| P3. Czy korelacja poprawia wyniki względem prostego baseline (np. SSID/BSSID)? | eksperymenty Evil Twin, ablacja poszczególnych sygnałów | 5.5–5.7 i 6.2–6.3 |
| P4. Jaki jest czas detekcji, częstość fałszywych alarmów i koszt sprzętowy? | real RF, negatywne kontrole, eksperymenty wielu AP/sensorów | 5.5–5.8 i 6.2–6.5 |

## 3. Struktura oddawanej pracy

| Część | Treść | Orientacyjnie |
|---|---|---:|
| Wstęp | istota problemu, cel, zakres, pytania, układ pracy | 3–4 strony |
| **1. Analiza problemu i istniejących rozwiązań** | zagrożenie, odbiorcy/rynek, analiza konkurencji, publikacje naukowe, luka inżynierska | 9–11 |
| **2. Podstawy techniczne i metody detekcji** | IEEE 802.11, SSID/BSSID, IE, TSF/clock skew, RSSI, sequence, deauth/PMF, baseline, reguły i korelacja | 8–10 |
| **3. Wymagania i projekt systemu** | funkcjonalne/niefunkcjonalne, model zagrożenia, architektura sensora/Blue oraz Red test-lab, uzasadnienie wyborów | 8–10 |
| **4. Implementacja** | faktycznie wdrożone elementy, algorytmy, API, dashboard, laboratorium i ograniczenia | 8–10 |
| **5. Metodyka badań** | jednostka ewaluacji, ground truth, stanowisko, scenariusze, metryki, baseline, kalibracja i izolacja testu | 6–8 |
| **6. Wyniki badań i dyskusja** | liczby, wykresy, analiza błędów, ablacja, sprzęt, warunki ważności | 9–12 |
| Zakończenie | odpowiedzi na P1–P4, zakres rozwiązania, ograniczenia i dalszy rozwój | 2–3 |

**55–65 stron tekstu głównego** jest celem redakcyjnym, a nie oficjalnym limitem PJATK. Warunki redakcyjne sprawdzić ponownie przed końcowym składem, a rozbieżności skonsultować z promotorem. Oficjalna wersja dotyczy **pracy inżynierskiej** (nie zmieniać typu dyplomu w nagłówkach).

## 4. Rozdziały a stan oprogramowania

- **1–2:** mogą powstawać obecnie na podstawie aktualnych dokumentacji i literatury. Nie opisywać wyników własnego detektora.
- **3:** po audycie P0 spisać wymagania *wynikające z problemu*, a nie bezkrytycznie z obecnego kodu; zaznaczyć kompromisy.
- **4:** tylko po ponownym uruchomieniu testów i weryfikacji funkcji; osobno `zaimplementowane`, `w trakcie`, `niezrealizowane`. Nie opisywać Active Verification czy ML jako wdrożonych.
- **5:** metodykę zdefiniować **przed eksperymentami**. Ustalić jednostkę detekcji: próba/atak/okno, a nie liczba ramek.
- **6:** wyniki wpisać wyłącznie na podstawie plików danych, skryptów liczących miary i protokołów. Wykazać niepewność, wyjątki, przeoczenia i false positives.

## 5. Program eksperymentalny (zakres niezbędny)

1. **Stabilność cech (P2)**: AP różnych modeli, powtarzane sesje i restart, różne warunki RSSI/odległości; mierzyć odchylenia wewnątrz urządzenia vs pomiędzy urządzeniami, liczbę próbek do konwergencji zegara.
2. **Wykrywalność (P3, P4)**: normalny AP, drugi legalny AP z tym samym SSID, rogue SSID clone, clone BSSID, same/different channel, scenariusze bez deauth i — jeśli autoryzowane w odizolowanym laboratorium — z kontrolowanymi rozłączeniami. Mierzyć detection/TTD per próba.
3. **False positives (P3, P4)**: dłuższy benign monitoring, roaming, wahania RSSI, restart, zmiana kanału, hotspot, sieć o wielu BSSID. Mierzyć FP per godzina i FPR przy jawnej jednostce oceny.
4. **Ablacja (P3)**: pełna korelacja vs prosta kontrola SSID/BSSID; ocena po wyłączeniu pojedynczych modułów przy identycznych danych. Progi stroić poza zbiorem końcowego testu.
5. **Przenośność sprzętowa (P2, P4)**: istniejący RTL8812AU i drugi chipset, co najmniej dwa różne AP/firmware; odnotować, czy dany adapter raportuje TSF, RSSI i IE poprawnie. Nie kupować sprzętu bez weryfikacji wsparcia przez docelowy kernel/driver.

**Minimalny wynik do obrony:** powtarzalny benchmark na realnym RF, z pełnym ground truth, confusion matrix, TTD, FPR, ablacją i omówieniem ograniczeń. Same generowane PCAP-y i historyczne unit tests nie wystarczą.

## 6. Ograniczenia metodologiczne

- Wynik `score` nie jest prawdopodobieństwem bez kalibracji.
- Nie mieszać ramek tego samego AP w train/test przy eksperymentach ML. ML jest opcjonalne.
- Nie twierdzić, że „nowy AP”, „silny RSSI”, „zmieniony IE” lub „deauth flood” samodzielnie dowodzą Evil Twin.
- Odróżniać `rogue AP` (nieautoryzowany) od `Evil Twin` (podszywający się).
- Dane syntetyczne: regresja. Dane RF: dowód użyteczności w kontrolowanych warunkach. Nie ekstrapolować z kilku adapterów na wszystkie chipsety.
- Jeśli zewnętrzne rozwiązania nie zostały uruchomione na identycznych scenariuszach, porównanie konkurencji jest **jakościowe/funkcjonalne**, nie porównaniem skuteczności.
- Red nie może ujawniać prawdziwej etykiety próby do Blue podczas detekcji.

## 7. Wymagania promotora — kontrola

- [x] Problem, istotność i rozpoznanie innych rozwiązań — przewidziane w rozdziale 1.
- [x] Projekt i uzasadnienie decyzji — rozdział 3.
- [x] Wykonana implementacja — rozdział 4.
- [x] Rzeczywiste testy i analiza wyników — rozdziały 5–6 (jeszcze **niezrealizowane w wymaganym zakresie**).
- [x] Odpowiedź, co działa, nie działa i jak rozwijać — zakończenie.
- [x] Potencjalna przydatność rynkowa — porównanie funkcjonalne, bez niezweryfikowanych obietnic.
- [x] Możliwość ograniczenia zakresu do najważniejszych komponentów — P0/P1 i laboratoryjne P2 są ważniejsze od Active/ML.

## 8. Odnośniki i wersjonowanie

- Bieżący backlog techniczny: [PROJECT-ROADMAP.md](PROJECT-ROADMAP.md).
- Instrukcja testowania: [CLAUDE-REPO-AUDIT.md](CLAUDE-REPO-AUDIT.md).
- Stary plan `../wiguard-plan-v2.md` jest **archiwalną wizją**. Nie traktować stanu planu jako stanu kodu.
- Rękopis pracy istnieje jako osobny dokument roboczy; jego aktualizacje muszą wynikać z audytu i zmierzonych wyników. Plan w tym pliku jest spójny z redakcją v0.3 i nie zastępuje pełnego tekstu.
