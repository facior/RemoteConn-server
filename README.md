# RemoteConn Server

Serwer ID dla aplikacji RemoteConn (zdalny pulpit w stylu AnyDesk, repozytorium **RemoteConn-app**). Jeden proces, jeden port
**UDP 21116**:

- **rendezvous:** nadaje komputerom 9-cyfrowe ID i pomaga im połączyć się bezpośrednio przez NAT;
- **relay:** przekazuje ruch, gdy połączenie bezpośrednie się nie uda. Widzi wyłącznie szyfrogram, bo sesje są
  szyfrowane end-to-end;
- **panel WWW:** urządzenia, sesje relay, blokady, konta, zdarzenia i audyt. Działa tylko na `127.0.0.1`, a dostaje się
  do niego przez tunel SSH;
- **konta użytkowników:** łączenie bez hasła między własnymi komputerami. Serwer zna tylko klucze publiczne kont i nie
  może nikogo wpuścić do cudzego komputera.

```
 [komputer A] ⇄ szyfrowanie end-to-end (QUIC + Noise) ⇄ [komputer B]
       │          bezpośrednio (P2P) albo przez relay
       └──────────── RemoteConn Server (UDP 21116) ────────────┘
```

## Szybki start (Linux)

Debian, Ubuntu, Fedora albo RHEL/Rocky/Alma z systemd. Na serwerze:

```sh
git clone https://github.com/facior/RemoteConn-server.git
cd RemoteConn-server
sudo bash ./deploy/install.sh --harden-ssh --fail2ban --auto-updates
```

Instalator kompiluje serwer i uruchamia go jako usługę systemd z izolacją. Ustawia też zaporę i generuje klucz dostępu.
Potem prowadzi przez konfigurację panelu WWW: konto administratora i **2FA** (kod QR do zeskanowania telefonem),
więc przygotuj aplikację uwierzytelniającą. Na końcu wypisuje **adres, klucz dostępu i odcisk serwera**; te trzy
wartości wpisujesz w aplikacji (Ustawienia → Sieć). Zapisuje je też w `/root/remoteconn-credentials.txt`.

`--harden-ssh` wyłącza logowanie hasłem do SSH tylko wtedy, gdy któryś administrator (root albo konto z sudo) ma już
klucz SSH. Najpierw wgraj klucz (`ssh-copy-id użytkownik@serwer`).

Pełny przewodnik krok po kroku (VPS, klucze SSH, DNS, kopie zapasowe, przeprowadzka, problemy):
**[docs/INSTALACJA-SERWERA.md](docs/INSTALACJA-SERWERA.md)**.

### Docker

```sh
cd deploy
# ustaw RC_ACCESS_KEY w docker-compose.yml
docker compose up -d
docker compose exec rc-server rc-server panel-user add admin
```

### Uruchomienie lokalne (testy, programowanie)

```sh
cargo run --release -p rc-server            # nasłuchuje na 0.0.0.0:21116, dane w ./data
```

## Konfiguracja

Zmienne środowiskowe (instalator zapisuje je w `/etc/remoteconn/server.env`):

| Zmienna | Domyślnie | Znaczenie |
|---|---|---|
| `RC_ACCESS_KEY` | brak | **zalecane:** klucz, który muszą podać klienci; bez niego serwer jest otwarty dla każdego |
| `RC_BIND` | `0.0.0.0:21116` | adres UDP |
| `RC_DATA_DIR` | `./data` | rejestr urządzeń, certyfikat, blokady, konta (instalator: `/var/lib/remoteconn`) |
| `RC_RELAY_ADDR` | ten serwer | osobny relay `host:port` |
| `RC_MAX_RELAYS` | `200` | równoczesne sesje relay |
| `RC_MAX_CONN_PER_CLIENT` | `32` | połączenia na IP / sieć IPv6 /64 |
| `RC_ADMIN_BIND` | `127.0.0.1:8080` | panel WWW; `off` wyłącza |
| `RC_ADMIN_HOSTS` | brak | dodatkowe nazwy hosta panelu (tylko bez tunelu SSH) |
| `RC_ACCOUNTS` | `invite` | zakładanie kont: `invite` (kody od administratora), `open`, `off` |

Nie kasuj `server.key` ani `server.crt` w katalogu danych: aplikacje przypinają certyfikat serwera i odmówią
połączenia, gdy się zmieni.

## Administracja

Na serwerze zainstalowanym przez `install.sh` służy do tego `rc-admin` (tylko root; każda zmiana trafia do dziennika):

```sh
sudo rc-admin status                    # stan usługi, port, odcisk, urządzenia, panel, konta
sudo rc-admin logs -f                   # dziennik na bieżąco
sudo rc-admin block device 123456789    # blokada urządzenia (także ip / net), działa od razu
sudo rc-admin key rotate                # nowy klucz dostępu
sudo rc-admin account invite "Anna"     # kod zaproszenia na konto (jednorazowy, 7 dni)
sudo rc-admin panel setup               # konto do panelu WWW z 2FA (przewodnik, jak przy instalacji)
sudo rc-admin backup ~                  # kopia danych i konfiguracji
sudo rc-admin update                    # po git pull: przebudowa i restart
sudo rc-admin help                      # wszystkie polecenia
```

### Panel WWW

Panel nasłuchuje tylko na `127.0.0.1:8080`. Z własnego komputera:

```sh
ssh -N -L 8080:127.0.0.1:8080 admin@<serwer>
```

i w przeglądarce **http://localhost:8080**. Panel ma zakładki: przegląd, urządzenia (z przyciskiem „Połącz”, który
otwiera aplikację), konta i zaproszenia, sesje relay, blokady, zdarzenia oraz audyt. Logowanie chronią Argon2id,
opcjonalne 2FA (TOTP) i blokada po nieudanych próbach.

## Bezpieczeństwo w skrócie

- **Ruch:** serwer widzi tylko szyfrogram (Noise end-to-end). Hasła do komputerów nigdy przez niego nie przechodzą
  (SPAKE2).
- **Ochrona przed nadużyciami:** klucz dostępu, weryfikacja adresów (QUIC Retry), limity połączeń, zapytań, nowych
  urządzeń i sesji relay, lista blokad stosowana bez restartu.
- **Przejęcie serwera:** atakujący nie odczyta sesji i nie wpuści nikogo do komputerów, bo konta opierają się na
  kluczach liczonych z hasła na urządzeniach. Może blokować połączenia i widzieć metadane (kto, z kim, kiedy).
- **Instalacja:** osobny użytkownik bez powłoki, sandbox systemd, sekrety 0600, opcjonalnie SSH tylko na klucze,
  fail2ban i automatyczne aktualizacje.

Szczegóły (model zagrożeń, panel, konta, rozwiązywanie problemów): **[docs/SERWER.md](docs/SERWER.md)**.

## Zgodność z aplikacją

Katalog `crates/` zawiera protokół wspólny z aplikacją: `rc-proto`, `rc-crypto`, `rc-transport` i `rc-rendezvous`.
Źródłem prawdy jest repozytorium aplikacji. Po zmianie protokołu uruchom tam `scripts/sync-shared.ps1`, który
skopiuje te biblioteki tutaj, i zatwierdź zmiany w obu repozytoriach. Testy połączeń w repozytorium aplikacji
uruchamiają program `rc-server` z tego repozytorium.

## Struktura

| Ścieżka | Zawartość |
|---|---|
| `rc-server/src/` | serwer: rendezvous, relay, limity, blokady, konta (`accounts.rs`), panel WWW (`admin/`) |
| `rc-server/tests/` | testy API panelu i kont na prawdziwym serwerze |
| `crates/` | protokół wspólny z aplikacją (kopia, patrz wyżej) |
| `deploy/install.sh` | instalator Linux (systemd, zapora, zabezpieczenia SSH) |
| `deploy/rc-admin` | narzędzie administratora |
| `deploy/Dockerfile`, `deploy/docker-compose.yml` | obraz Docker |
| `docs/` | opis serwera i przewodnik instalacji |

## Programowanie

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
shellcheck -s bash deploy/install.sh deploy/rc-admin
```

Instalator buduje z `--locked`, więc po zmianie zależności zatwierdź zaktualizowany `Cargo.lock`.
