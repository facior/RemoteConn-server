# RemoteConn Server: opis, bezpieczeństwo i administracja

Serwer ID (rendezvous + relay) z panelem WWW i kontami użytkowników. Instalacja krok po kroku:
[INSTALACJA-SERWERA.md](INSTALACJA-SERWERA.md). Aplikacja desktopowa jest w osobnym repozytorium (RemoteConn-app).

---

## 1. Serwer: co robi i kiedy przechodzi przez niego ruch

Serwer ma dwie role w jednym procesie, na jednym porcie **UDP 21116**.

**1. Rendezvous (zawsze przy łączeniu po ID, tylko kilka małych wiadomości)**
- Host rejestruje się na serwerze i podpisuje rejestrację swoim kluczem. Serwer przydziela 9-cyfrowe ID na stałe
  powiązane z tym kluczem, więc nikt nie przejmie cudzego ID.
- Host trzyma lekkie połączenie (keepalive), dzięki czemu serwer wie, że jest online, i zna jego publiczny adres.
- Viewer pyta o ID i dostaje adres oraz klucz publiczny hosta. Serwer każe hostowi wysłać pakiety w stronę viewera,
  co otwiera przejście przez NAT. Jeśli połączenie bezpośrednie się uda, serwer nie bierze dalej udziału.

**2. Relay (plan awaryjny)**
- Gdy w ~4 s nie uda się połączenie bezpośrednie (NAT symetryczny, sieci komórkowe, CGNAT, firmowe zapory),
  obie strony łączą się z serwerem, a on przekazuje między nimi cały ruch.

**Co serwer widzi:** wyłącznie szyfrogram. Szyfrowanie jest end-to-end, a hasło nigdy nie przechodzi przez sieć.
Serwer zna tylko adresy IP, czas trwania sesji i ilość danych.

**Gdyby ktoś przejął serwer:** nie odczyta sesji ani nie podszyje się pod hosta (aplikacja sprawdza klucz hosta,
a bez hasła nie przejdzie uwierzytelnienia). Mógłby blokować połączenia albo zbierać metadane, czyli kto, z kim
i kiedy się łączy. Dlatego aplikacja przypina klucz serwera i odmawia połączenia, gdy się zmieni.

**Zasoby:**

| Sytuacja | Obciążenie |
|---|---|
| Host online, bez sesji | praktycznie zero |
| Sesja P2P | zero |
| Sesja przez relay | 1–8 Mb/s w każdą stronę; ruch liczony podwójnie (odbiór + wysyłka) |

Dla małej firmy wystarczy najtańszy VPS (1 vCPU, 1 GB RAM, łącze 100 Mb/s+, publiczny adres IP). Zwróć uwagę na
limit transferu: godzina sesji przez relay przy ~4 Mb/s to około 2 GB w jedną stronę.

## 2. Instalacja serwera na Linuxie

Szczegółowy przewodnik krok po kroku (VPS, klucze SSH, przesłanie projektu, kopie, przeprowadzka, problemy):
**[INSTALACJA-SERWERA.md](INSTALACJA-SERWERA.md)**. Poniżej skrót.

### 2.1 Wymagania

- Debian 11+, Ubuntu 20.04+, Fedora, RHEL/Rocky/Alma 9 (systemd, apt albo dnf).
- Publiczny adres IP (albo przekierowany port UDP 21116).
- Ok. 2 GB RAM do kompilacji. Przy mniejszej ilości skrypt sam założy tymczasowy swap.
- Dostęp root (sudo).

### 2.2 Kroki

1. Skopiuj repozytorium na serwer, np.:
   ```sh
   git clone <adres-twojego-repozytorium> remoteconn
   # albo z Windows: scp -r D:\RemoteConn-server uzytkownik@serwer:~/remoteconn
   ```
2. Zainstaluj (zalecany zestaw z zabezpieczeniami admina):
   ```sh
   cd remoteconn
   sudo bash ./deploy/install.sh --harden-ssh --fail2ban --auto-updates
   ```
   `--harden-ssh` wyłącza logowanie hasłem do SSH. Skrypt odmówi, jeśli nie masz klucza SSH na koncie, z którego
   uruchamiasz sudo, więc nie zablokujesz sobie dostępu. Najpierw zrób `ssh-copy-id uzytkownik@serwer`.
3. Na końcu skrypt wypisze **adres serwera, klucz dostępu, odcisk serwera i kod konfiguracji** (`RC1-…`). Zapisze je
   też w `/root/remoteconn-credentials.txt` (tylko root); pokaże je ponownie `sudo rc-admin app`.
4. W aplikacji: **Ustawienia → Sieć → „Wklej kod”**, wklej kod konfiguracji i zapisz. Adres, klucz i zaufany odcisk
   serwera ustawią się naraz. Można też wpisać adres i klucz ręcznie i kliknąć „Testuj”; wtedy odcisk pokazany w
   aplikacji musi być taki sam jak ten z instalatora. Włącz udostępnianie, a pojawi się ID.

### 2.3 Opcje instalatora

| Opcja | Znaczenie |
|---|---|
| `--port PORT` | port UDP (domyślnie 21116) |
| `--access-key KLUCZ` | własny klucz (min. 16 znaków); domyślnie losowy, 32 znaki |
| `--relay-addr HOST:PORT` | ogłaszaj osobny relay |
| `--max-relays N` | limit równoczesnych sesji relay (200) |
| `--max-conn N` | limit połączeń na IP / sieć IPv6 /64 (32) |
| `--admin-port PORT` | port panelu WWW, zawsze tylko na 127.0.0.1 (8080) |
| `--no-panel` | bez panelu WWW |
| `--no-firewall` | nie zmieniaj zapory |
| `--harden-ssh` | SSH tylko na klucze, root bez hasła, max 3 próby |
| `--fail2ban` | blokada IP po 5 nieudanych logowaniach SSH (1 h, rośnie przy powtórkach) |
| `--auto-updates` | automatyczne aktualizacje bezpieczeństwa systemu |
| `--yes` | instalacja bez pytań |
| `--update` | przebudowa z repozytorium i restart (klucz i dane zostają) |
| `--uninstall [--purge]` | usunięcie usługi (z `--purge` także danych) |

### 2.4 Co robi instalator

1. Instaluje narzędzia do kompilacji i Rust (osobno, w `/opt/remoteconn`, bez zmian w systemowym PATH).
2. Kompiluje `rc-server` i instaluje go do `/usr/local/bin`.
3. Tworzy użytkownika systemowego `remoteconn` bez powłoki i hasła. Dane trafiają do `/var/lib/remoteconn` (0700).
4. Generuje losowy klucz dostępu i zapisuje konfigurację w `/etc/remoteconn/server.env` (0600, tylko root).
5. Instaluje usługę systemd `remoteconn-server` z izolacją:
   - brak jakichkolwiek uprawnień i capabilities, system plików tylko do odczytu poza katalogiem danych;
   - brak dostępu do `/home`, urządzeń i innych procesów;
   - tylko gniazda sieciowe, filtr wywołań systemowych.
6. Zwiększa bufory UDP dla QUIC.
7. Konfiguruje zaporę:
   - ufw: SSH z limitem prób, port serwera, reszta zablokowana;
   - firewalld: SSH i port serwera.

   Port SSH jest dodawany **przed** włączeniem zapory, więc nie stracisz połączenia.
8. Instaluje `rc-admin` (tylko root) i dziennik działań administratora.
9. Włącza panel WWW na 127.0.0.1:8080 (port nie jest otwierany w zaporze) i proponuje utworzenie konta.
10. Opcjonalnie utwardza SSH, instaluje fail2ban i automatyczne aktualizacje.

### 2.5 Alternatywa: Docker

```sh
cd server/deploy
# ustaw RC_ACCESS_KEY w docker-compose.yml
docker compose up -d
```

Docker nie konfiguruje zapory, SSH ani `rc-admin`. Do produkcji zalecany jest `install.sh`.
Panel WWW jest w `docker-compose.yml` wystawiony tylko na `127.0.0.1:8080` hosta; konto tworzysz poleceniem
`docker compose exec rc-server rc-server panel-user add admin`.

## 3. Administracja (`rc-admin`)

Wszystkie polecenia wymagają `sudo`. Każda zmiana trafia do `/var/log/remoteconn-admin.log` (kto, kiedy, co).

| Polecenie | Co robi |
|---|---|
| `rc-admin status` | stan usługi, port, odcisk, liczba urządzeń i blokad, klucz, zapora |
| `rc-admin logs [-f]` | dziennik serwera |
| `rc-admin devices` | zarejestrowane urządzenia (ID, nazwa) |
| `rc-admin block ip 203.0.113.5` | blokada adresu |
| `rc-admin block net 198.51.100.0/24` | blokada sieci (IPv4 i IPv6) |
| `rc-admin block device 123456789` | blokada urządzenia: rozłącza je od razu, a jego ID wygląda dla innych jak nieznane |
| `rc-admin unblock <wartość>` | zdjęcie blokady |
| `rc-admin blocklist` | lista blokad |
| `rc-admin key show` | pokazuje klucz dostępu |
| `rc-admin key rotate` | nowy klucz (np. po wycieku); klienci muszą go wpisać w ustawieniach |
| `rc-admin app` | dane do aplikacji: kod konfiguracji `RC1-…` do wklejenia (Ustawienia → Sieć → „Wklej kod”) oraz adres, klucz i odcisk |
| `rc-admin address [host[:port]]` | pokazuje albo ustawia publiczny adres (np. domenę) używany w kodzie konfiguracji |
| `rc-admin fingerprint` | odcisk certyfikatu do porównania z aplikacją |
| `rc-admin config` | konfiguracja (klucz ukryty) |
| `rc-admin restart` | restart usługi |
| `rc-admin backup [katalog]` | kopia danych i konfiguracji (zawiera klucze, więc przechowuj bezpiecznie) |
| `rc-admin audit` | dziennik działań administratora |
| `rc-admin update [vX.Y.Z]` | instalacja wydania (domyślnie najnowszego) z powrotem do poprzedniej wersji przy błędzie |
| `rc-admin update check` / `update status` | sprawdzenie nowych wydań (robi to też codzienny timer) / wynik ostatniej aktualizacji |
| `rc-admin panel setup` | przewodnik: konto administratora panelu + 2FA (to samo co przy instalacji) |
| `rc-admin panel url` | polecenie tunelu SSH do panelu WWW |
| `rc-admin panel user list\|add\|passwd\|totp\|totp-off\|remove <nazwa>` | konta panelu (hasło min. 12 znaków, 2FA z kodem QR) |
| `rc-admin panel audit` | logowania i zmiany wykonane w panelu |
| `rc-admin panel off` / `panel on [port]` | wyłączenie / włączenie panelu |
| `rc-admin account list\|invite\|disable\|enable\|delete` | konta użytkowników (rozdz. 7) |
| `rc-admin accounts mode invite\|open\|off` | kto może zakładać konta |

Blokady działają **bez restartu**: serwer sprawdza listę co kilka sekund. Lista jest w
`/var/lib/remoteconn/blocklist.txt`.

### 3.1 Panel WWW

Wbudowany w `rc-server` (bez dodatkowych usług). Zakładki:
- **Przegląd:** liczba urządzeń online i zarejestrowanych, sesje relay, przesłane dane, czas działania, odcisk
  certyfikatu, czy klucz dostępu jest ustawiony. Karta **„Dane do aplikacji”** pokazuje po kliknięciu kod
  konfiguracji `RC1-…` oraz adres, klucz i odcisk, każde z przyciskiem „Kopiuj”. Kod zawiera klucz dostępu, więc każde
  wyświetlenie trafia do dziennika działań;
- **Urządzenia:** wyszukiwanie po nazwie lub ID, stan, adres, od kiedy online. Przyciski:
  - **Połącz** otwiera aplikację RemoteConn na komputerze administratora z wpisanym ID (link
    `remoteconn://connect?id=…`); hasło wpisuje się w aplikacji, a samo połączenie jest jak zwykle szyfrowane
    end-to-end;
  - **Rozłącz** wymusza ponowną rejestrację;
  - **Zablokuj** / **Odblokuj**;
- **Relay:** aktywne sesje przez serwer (adresy obu stron, czas, bajty; nigdy treść), z możliwością zakończenia;
- **Blokady:** dodawanie i usuwanie wpisów (te same co `rc-admin block`);
- **Zdarzenia:** urządzenia online/offline, sesje relay, blokady, działania administratorów (ostatnie 500, w pamięci);
- **Audyt:** logowania (także nieudane) i zmiany z panelu (`/var/lib/remoteconn/panel-audit.log`).

Dostęp: panel nasłuchuje tylko na `127.0.0.1:8080`. Na swoim komputerze uruchom
`ssh -N -L 8080:127.0.0.1:8080 admin@serwer` i otwórz `http://localhost:8080`. Ruch idzie wtedy szyfrowanym tunelem
SSH, a do panelu dostaje się tylko ktoś, kto ma już dostęp SSH do serwera.

Zabezpieczenia:

| Zagrożenie | Ochrona |
|---|---|
| Zgadywanie hasła | Argon2id, 5 błędów na konto lub 20 z jednego adresu = blokada na 15 min, opóźnienie po błędzie, równoległe sprawdzanie ograniczone |
| Kradzież hasła | opcjonalne 2FA (TOTP), kod działa tylko raz |
| Wykrywanie kont | nieznany użytkownik jest sprawdzany tak samo długo jak znany; ten sam komunikat błędu |
| Przejęcie sesji | ciasteczko HttpOnly + SameSite=Strict, serwer trzyma tylko jego hash, wygasa po 30 min bezczynności / 12 h |
| CSRF | token w nagłówku przy każdej zmianie, sprawdzanie Origin, tylko JSON |
| DNS rebinding | panel odpowiada tylko na `localhost`/`127.0.0.1` (inne nazwy: `RC_ADMIN_HOSTS`) |
| XSS / clickjacking | ścisłe CSP (bez skryptów inline), zakaz ramek, dane wstawiane jako tekst |
| Usunięte konto | traci sesje natychmiast |

Czego panel nie robi: nie zmienia klucza dostępu ani konfiguracji (to pliki roota, służy do tego `rc-admin`) i nie
widzi treści sesji.

## 4. Zabezpieczenia dla administratora (podsumowanie)

| Warstwa | Zabezpieczenie |
|---|---|
| Dostęp do serwera | SSH tylko na klucze, root bez hasła, max 3 próby, limit prób w zaporze, fail2ban |
| System | automatyczne aktualizacje bezpieczeństwa, zapora domyślnie blokująca |
| Usługa | osobny użytkownik bez powłoki, sandbox systemd, zero uprawnień, pliki tworzone jako 0600 |
| Sekrety | konfiguracja z kluczem tylko dla roota (0600), klucz prywatny serwera 0600, dane serwera 0700 |
| Narzędzia | `rc-admin` tylko dla roota, operacje na danych wykonywane jako użytkownik usługi, dziennik audytu |
| Panel WWW | tylko 127.0.0.1 + tunel SSH, Argon2id, 2FA, blokada prób, CSRF/CSP/DNS rebinding, dziennik audytu (3.1) |
| Serwis | klucz dostępu, limity połączeń, zapytań i nowych urządzeń, limit relay, lista blokad, weryfikacja adresów |

Zalecenia:
- po instalacji z `--harden-ssh` sprawdź logowanie w **nowym** oknie, zanim zamkniesz obecne;
- zmieniaj klucz dostępu (`rc-admin key rotate`), gdy ktoś przestaje mieć dostęp;
- rób kopie (`rc-admin backup`) i trzymaj je poza serwerem;
- przeglądaj `rc-admin logs` i `rc-admin audit`.

## 5. Rozwiązywanie problemów

| Objaw | Co sprawdzić |
|---|---|
| „Serwer ID jest nieosiągalny” | `rc-admin status`; czy UDP 21116 jest otwarty także w panelu dostawcy VPS (security group) |
| „Serwer ID odrzucił klucz dostępu” | klucz w aplikacji ↔ `rc-admin key show` |
| „Klucz serwera ID jest inny niż przy pierwszym połączeniu” | czy serwer był reinstalowany; jeśli nie, możliwy atak; jeśli tak: „Zapomnij klucz serwera” |
| ID nie pojawia się po włączeniu udostępniania | adres serwera i klucz w ustawieniach; status „offline” ma podpowiedź z przyczyną |
| Zawsze „Relay” zamiast „P2P” | normalne przy NAT symetrycznym i CGNAT; działa, tylko przez serwer |
| Usługa nie startuje | `rc-admin logs`, `journalctl -u remoteconn-server` |
| Instalacja przerwana przy kompilacji | brak pamięci: skrypt zakłada swap, ale na bardzo małych VPS kompiluj z większym RAM-em |

## 6. Przydatne ścieżki

| Ścieżka | Zawartość |
|---|---|
| `/usr/local/bin/rc-server` | serwer |
| `/usr/local/sbin/rc-admin` | narzędzie administratora |
| `/etc/remoteconn/server.env` | konfiguracja i klucz dostępu (0600) |
| `/var/lib/remoteconn/` | rejestr urządzeń, certyfikat i klucz serwera, lista blokad |
| `/var/lib/remoteconn/panel-users.json` | konta panelu WWW (hashe Argon2id, sekrety 2FA; 0600) |
| `/var/lib/remoteconn/panel-audit.log` | dziennik logowań i zmian z panelu |
| `/var/log/remoteconn-admin.log` | dziennik działań administratora |
| `/root/remoteconn-credentials.txt` | dane dla klientów (0600) |
| `/var/lib/remoteconn/accounts.json` | konta użytkowników: klucze publiczne, sole, urządzenia, zaproszenia (0600) |

## 7. Konta (łączenie bez hasła między własnymi komputerami)

Jak w AnyViewer: logujesz się na to samo konto na swoich komputerach, w „Moich komputerach” widzisz, które są online,
i łączysz się jednym kliknięciem, bez hasła. RemoteConn robi to jednak tak, że **serwer nie może wpuścić nikogo
do Twoich komputerów**, nawet gdyby ktoś go przejął.

**Jak to działa:**
1. Z hasła konta aplikacja liczy na Twoim komputerze klucz konta (Argon2id, 64 MiB). Serwer dostaje tylko klucz
   publiczny i sól, nigdy hasło.
2. Logowanie: aplikacja podpisuje kluczem konta jednorazowe wyzwanie od serwera.
3. Przy logowaniu urządzenie wystawia sobie **certyfikat**: kluczem konta podpisuje swój klucz urządzenia (ważny rok,
   każde logowanie go odnawia). Klucz prywatny konta znika z pamięci zaraz potem.
4. Komputer na koncie zapamiętuje klucz publiczny konta (opcja „Wpuszczaj moje urządzenia bez hasła”). Gdy łączy się
   urządzenie z ważnym certyfikatem tego konta, host wpuszcza je bez hasła i bez okna akceptacji. Szyfrowanie Noise
   dowodzi przy tym, że urządzenie ma klucz z certyfikatu, więc skopiowany certyfikat na nic się nie przyda.

**Konta zakłada się z kodem zaproszenia** (domyślnie, `RC_ACCOUNTS=invite`): administrator tworzy kod w panelu
(zakładka Konta) albo `rc-admin account invite`, a użytkownik wpisuje go w Ustawienia → Konto → Nowe konto.
Można też pozwolić każdemu (`open`) albo wyłączyć konta (`off`).

**Utrata urządzenia:** Ustawienia → Konto → „Odbierz dostęp” przy urządzeniu (albo administrator w panelu). Serwer
od razu powiadamia komputery konta, które są online, a te przestają wpuszczać to urządzenie. Hosty tylko dopisują
odebrane urządzenia do listy, nigdy ich z niej nie usuwają, więc przejęty serwer nie przywróci dostępu skradzionemu
laptopowi.

**Zmiana hasła:** stary klucz podpisuje nowy. Komputery konta przyjmują nowy klucz automatycznie (sprawdzają podpis,
więc serwer nie może podsunąć własnego klucza), a certyfikaty starego klucza przestają działać: na pozostałych
urządzeniach, z których się łączysz, zaloguj się ponownie.

| Kto przejmie… | może | nie może |
|---|---|---|
| serwer | blokować połączenia, widzieć listę urządzeń kont | wpuścić kogokolwiek do Twoich komputerów, poznać hasła, podmienić klucza konta |
| hasło do konta | łączyć się z Twoimi komputerami (jak właściciel) | nic więcej; po zmianie hasła i odebraniu dostępu urządzeniom traci dostęp |
| kopię pliku z certyfikatem | nic, bez klucza prywatnego urządzenia (DPAPI) | — |

**Administrator** w panelu (zakładka Konta) widzi konta i ich urządzenia, może tworzyć zaproszenia, blokować
i usuwać konta oraz odbierać dostęp urządzeniom. Zablokowanie konta działa od razu na komputerach online. Resetu
hasła nie ma, bo serwer go nie zna: konto trzeba usunąć i założyć od nowa, a komputery trzeba zalogować ponownie
(to celowe: administrator serwera nie może przejąć cudzych komputerów).
