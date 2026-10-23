# Instalacja serwera RemoteConn: przewodnik krok po kroku

Ten przewodnik prowadzi od zera do działającego serwera ID (rendezvous + relay) na Linuxie i opisuje jego codzienną
obsługę. Komendy oznaczone **[Windows]** wpisujesz w PowerShellu na swoim komputerze, a **[serwer]** w terminalu
serwera po połączeniu przez SSH.

Opis tego, co serwer robi i jakie ma zabezpieczenia, jest w [SERWER.md](SERWER.md).

---

## 0. Lista rzeczy do przygotowania

- [ ] VPS z Linuxem (Debian 12 albo Ubuntu 24.04 to najprostszy wybór), publiczny adres IPv4
- [ ] dostęp root albo użytkownik z `sudo`
- [ ] klucz SSH na Twoim komputerze (krok 3)
- [ ] kopia repozytorium RemoteConn-server (krok 4)
- [ ] ok. 20 minut (większość to kompilacja)

## 1. Wybór serwera (VPS)

| Parametr | Minimum | Uwagi |
|---|---|---|
| CPU | 1 vCPU | serwer zużywa mało; liczy się łącze |
| RAM | 1 GB | do kompilacji instalator sam doda tymczasowy swap |
| Dysk | 10 GB | sam serwer zajmuje kilka MB; reszta to narzędzia kompilacji |
| Łącze | 100 Mb/s | dla relaya: każda sesja przez relay to 1–8 Mb/s w obie strony |
| Transfer | im więcej, tym lepiej | godzina sesji przez relay ≈ 2 GB w jedną stronę |
| Adres IP | publiczny IPv4 | bez tego serwer nie będzie osiągalny z internetu |
| Lokalizacja | blisko użytkowników | mniejsze opóźnienie przy relayu |

Upewnij się, że dostawca **nie blokuje ruchu UDP** (zwykle nie blokuje).

## 2. (Zalecane) Domena zamiast samego IP

Jeśli masz domenę, dodaj u jej dostawcy rekord DNS:

```
Typ: A    Nazwa: rc    Wartość: <IP serwera>    → rc.twojafirma.pl
```

W aplikacjach wpiszesz wtedy `rc.twojafirma.pl` zamiast adresu IP. Przy przeprowadzce na inny serwer zmienisz tylko
rekord DNS. Pamiętaj wtedy o przeniesieniu danych serwera (rozdział 12), bo inaczej aplikacje zobaczą nowy klucz
serwera i odmówią połączenia.

## 3. Klucz SSH i pierwsze logowanie

**[Windows]** Utwórz klucz (jeśli jeszcze go nie masz). Na pytania odpowiadaj Enterem, a hasło do klucza jest zalecane:

```powershell
ssh-keygen -t ed25519
```

**[Windows]** Skopiuj klucz na serwer. Pierwszy raz zaloguj się hasłem od dostawcy:

```powershell
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh root@<IP-serwera> "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

**[Windows]** Sprawdź, że logowanie działa bez hasła do serwera:

```powershell
ssh root@<IP-serwera>
```

### (Zalecane) Osobny użytkownik administratora zamiast roota

**[serwer]** (jako root):

```sh
adduser admin                       # Debian/Ubuntu (na Fedorze/RHEL: useradd -m admin && passwd admin)
usermod -aG sudo admin              # Debian/Ubuntu (na Fedorze/RHEL: usermod -aG wheel admin)
mkdir -p /home/admin/.ssh
cp ~/.ssh/authorized_keys /home/admin/.ssh/
chown -R admin:admin /home/admin/.ssh
chmod 700 /home/admin/.ssh && chmod 600 /home/admin/.ssh/authorized_keys
```

**[Windows]** Od teraz loguj się jako `admin`: `ssh admin@<IP-serwera>`.

## 4. Przesłanie repozytorium na serwer

Najprościej sklonować repozytorium bezpośrednio na serwerze (**[serwer]**: `git clone <adres-repozytorium> RemoteConn-server`).
Bez dostępu do gita spakuj katalog na Windows, pomijając katalog z kompilacji `target`.

**[Windows]**

```powershell
tar -czf $env:USERPROFILE\remoteconn.tar.gz --exclude=target --exclude=.git -C D:\ RemoteConn-server
scp $env:USERPROFILE\remoteconn.tar.gz admin@<IP-serwera>:~/
```

**[serwer]**

```sh
tar -xzf remoteconn.tar.gz
cd RemoteConn-server
```

## 5. Port w panelu dostawcy

Wielu dostawców ma własną zaporę w panelu („Firewall”, „Security group”). Zezwól tam na:

| Protokół | Port | Po co |
|---|---|---|
| TCP | 22 (albo Twój port SSH) | logowanie administratora |
| **UDP** | **21116** | serwer RemoteConn |

Zaporę w samym systemie (ufw/firewalld) ustawi instalator.

## 6. Instalacja

**[serwer]** w katalogu `RemoteConn-server`:

```sh
sudo bash ./deploy/install.sh --harden-ssh --fail2ban --auto-updates
```

- `--harden-ssh` wyłącza logowanie hasłem do SSH. Zadziała tylko wtedy, gdy masz klucz z kroku 3; w przeciwnym razie
  skrypt to pominie z ostrzeżeniem.
- `--fail2ban` blokuje adresy, które zgadują hasła SSH.
- `--auto-updates` instaluje same poprawki bezpieczeństwa systemu.

Inne opcje (port, własny klucz, limity) opisuje `sudo bash ./deploy/install.sh --help` i
[SERWER.md](SERWER.md#23-opcje-instalatora).

Kompilacja trwa kilka minut. Na końcu zobaczysz:

```
Gotowe. Dane dla klientów (zapisane też w /root/remoteconn-credentials.txt, tylko root):

Adres serwera ID:   203.0.113.10:21116
Klucz dostępu:      Xk3...(32 znaki)
Odcisk serwera:     5290-d8b4-3bd8-ce99
```

**Zapisz te trzy wartości.** W każdej chwili odczytasz je ponownie: `sudo cat /root/remoteconn-credentials.txt`.

Na końcu instalator przeprowadzi Cię przez konfigurację panelu WWW (rozdział 9, „Panel WWW”):
1. nazwa administratora (domyślnie `admin`) i hasło (co najmniej 12 znaków; przy za krótkim zapyta ponownie);
2. **2FA**: wyświetli kod QR, który skanujesz aplikacją uwierzytelniającą na telefonie (Google lub Microsoft
   Authenticator, Aegis, 1Password), a potem wpisujesz 6-cyfrowy kod, żeby potwierdzić.

Przygotuj telefon przed instalacją. Jeśli coś pominiesz, później uruchomisz ten sam przewodnik:
`sudo rc-admin panel setup`.

### Po `--harden-ssh`: sprawdź logowanie

**[Windows]** Otwórz **nowe** okno PowerShell i zaloguj się (`ssh admin@<IP-serwera>`). Dopiero gdy działa, zamknij
stare okno. Jeśli nie działa, w starym oknie usuń utwardzenie:
`sudo rm /etc/ssh/sshd_config.d/90-remoteconn-hardening.conf && sudo systemctl reload ssh` (na Fedorze/RHEL: `sshd`).

## 7. Sprawdzenie serwera

**[serwer]**

```sh
sudo rc-admin status          # usługa "active (running)", port, odcisk, klucz "ustawiony", zapora aktywna
sudo ss -ulpn | grep 21116    # serwer nasłuchuje na UDP 21116
sudo rc-admin logs            # ostatnie wpisy dziennika
```

## 8. Konfiguracja aplikacji na komputerach

Na każdym komputerze z RemoteConn:

1. **Ustawienia → Sieć**
2. **Serwer ID:** adres z kroku 6 (albo domena z kroku 2), port można pominąć, jeśli to 21116.
3. **Klucz dostępu:** wartość z kroku 6.
4. Kliknij **Testuj**. Powinno się pojawić „Serwer odpowiada … Klucz serwera: 5290-d8b4-3bd8-ce99 (zapamiętany jako
   zaufany)”. **Porównaj odcisk z tym z instalatora.** Muszą być identyczne.
5. **Zapisz**, wróć i kliknij **Zezwól na połączenia**. Przy „ID” pojawi się numer i status „online”.

### Test z zewnątrz

Połącz się z drugiego komputera w **innej sieci**, np. laptop na hotspocie z telefonu: wpisz ID i hasło. Pasek sesji
pokaże „P2P” (bezpośrednio) albo „Relay” (przez serwer). Oba oznaczają, że wszystko działa.

## 9. Codzienna obsługa

```sh
sudo rc-admin status                      # czy wszystko działa
sudo rc-admin logs -f                     # dziennik na bieżąco (Ctrl+C kończy)
sudo rc-admin logs | grep -E "host online|relay paired"   # kto się rejestruje, które sesje idą przez relay
sudo rc-admin devices                     # zarejestrowane urządzenia
```

**Blokowanie** (działa w ciągu kilku sekund, bez restartu):

```sh
sudo rc-admin block ip 203.0.113.5
sudo rc-admin block net 198.51.100.0/24
sudo rc-admin block device 123456789
sudo rc-admin blocklist
sudo rc-admin unblock 203.0.113.5
```

**Zmiana klucza dostępu** (np. gdy ktoś przestaje pracować w firmie):

```sh
sudo rc-admin key rotate
```

Potem wpisz nowy klucz w aplikacjach (Ustawienia → Sieć). Do tego czasu nie połączą się z serwerem.

**Dziennik działań administratora** (kto i kiedy coś zmieniał): `sudo rc-admin audit`.

### Panel WWW (w przeglądarce)

Serwer ma wbudowany panel: lista urządzeń (online/offline, adres, od kiedy), sesje przez relay (z liczbą
przesłanych bajtów), blokady, zdarzenia i dziennik zmian. Przy urządzeniach online jest przycisk **Połącz**, który
otwiera aplikację RemoteConn na Twoim komputerze z wpisanym ID; hasło podajesz w aplikacji.

Panel nasłuchuje **tylko na 127.0.0.1:8080**, więc z internetu go nie widać. Łączysz się przez tunel SSH.

**[serwer]** Konto z 2FA zakłada instalator. Jeśli go pominąłeś albo chcesz dodać kolejną osobę:

```sh
sudo rc-admin panel setup               # przewodnik: konto (hasło min. 12 znaków) + 2FA z kodem QR
```

**[Windows]** Za każdym razem, gdy chcesz użyć panelu, otwórz PowerShell:

```powershell
ssh -N -L 8080:127.0.0.1:8080 admin@<IP-serwera>
```

Zostaw to okno otwarte i wejdź w przeglądarce na **http://localhost:8080**. Gdy skończysz, zamknij okno (Ctrl+C).
`sudo rc-admin panel url` wypisuje to polecenie z właściwym adresem.

Zabezpieczenia panelu:
- hasła Argon2id i opcjonalne 2FA (kod działa tylko raz);
- 5 błędnych logowań na konto = blokada na 15 minut;
- sesja wygasa po 30 minutach bezczynności (najpóźniej po 12 godzinach);
- ochrona przed CSRF, clickjackingiem i DNS rebinding;
- każde logowanie i zmiana trafiają do `sudo rc-admin panel audit`.

Klucza dostępu nie zmienisz w panelu, tylko przez `rc-admin key rotate`, bo konfiguracja należy do roota.

### Konta użytkowników

Konta pozwalają łączyć się między własnymi komputerami bez haseł („Moje komputery” w aplikacji). Domyślnie zakłada
się je z kodem zaproszenia:

```sh
sudo rc-admin account invite "Anna z księgowości"    # wypisuje kod, np. 7KQ2-M8XA-PD3R (jednorazowy, 7 dni)
sudo rc-admin account list                            # konta i ich urządzenia
```

albo w panelu WWW, w zakładce **Konta**, gdzie można też blokować konta i odbierać dostęp zgubionym urządzeniom.
Użytkownik wpisuje kod w aplikacji: Ustawienia → Konto → Nowe konto. Kto może zakładać konta:
`sudo rc-admin accounts mode invite` (domyślnie), `open` (każdy, kto zna klucz dostępu do serwera) albo `off`.

Serwer nie zna haseł kont, więc nie ma ich resetu: zapomniane hasło oznacza usunięcie konta
(`sudo rc-admin account delete nazwa`) i nowe zaproszenie. Szczegóły i model bezpieczeństwa: [SERWER.md](SERWER.md), rozdział 7.

## 10. Kopie zapasowe

```sh
sudo rc-admin backup                      # tworzy /root/remoteconn-backup-DATA.tar.gz
```

Kopia zawiera rejestr urządzeń (ich ID), certyfikat i klucz serwera oraz klucz dostępu. **Trzymaj ją poza serwerem
i bezpiecznie.**

Pobranie kopii na swój komputer:

**[serwer]** Utwórz kopię od razu w swoim katalogu domowym:

```sh
sudo rc-admin backup ~ && sudo chown "$USER" ~/remoteconn-backup-*.tar.gz
```

**[Windows]**

```powershell
scp admin@<IP-serwera>:~/remoteconn-backup-*.tar.gz .
```

**[serwer]** Po pobraniu usuń kopię z katalogu domowego: `rm ~/remoteconn-backup-*.tar.gz`.

## 11. Aktualizacja serwera

Serwer raz dziennie sprawdza, czy w repozytorium na GitHubie jest nowe **wydanie** (tag `vX.Y.Z`). Sam niczego nie
instaluje: decyduje **główny administrator**, czyli pierwsze konto panelu, założone przy instalacji.

- **W panelu WWW:** na stronie „Przegląd” główny administrator widzi kartę „Aktualizacje serwera” z wersją
  zainstalowaną i dostępną oraz przyciskiem „Zaktualizuj”. Jego konto musi mieć włączone 2FA. Inni administratorzy
  tej karty nie widzą.
- **Z terminala:**
  ```sh
  sudo rc-admin update check      # sprawdź teraz
  sudo rc-admin update            # zainstaluj najnowsze wydanie (albo: sudo rc-admin update v0.3.0)
  sudo rc-admin update status     # jak poszła ostatnia aktualizacja
  ```

Aktualizacja przełącza repozytorium na wybrane wydanie, buduje serwer i uruchamia go ponownie. Trwa kilka minut, a
trwające połączenia przez relay zostaną przerwane. Jeśli nowa wersja nie wystartuje, wraca poprzednia, a szczegóły
są w `/var/log/remoteconn-update.log`. Klucz dostępu, ID urządzeń, konta i certyfikat zostają bez zmian, więc
aplikacje nie wymagają żadnej konfiguracji.

Główny administrator to rola pierwszego konta panelu. Przekazanie jej innemu kontu:
`sudo rc-server panel-user owner <nazwa>` (z `RC_DATA_DIR=/var/lib/remoteconn`, jako użytkownik `remoteconn`) albo
po prostu załóż konta w odpowiedniej kolejności.

> Serwer zainstalowany przed wersją 0.2.0 nie ma jeszcze aktualizacji z panelu. Jednorazowo:
> `cd ~/RemoteConn-server && sudo git pull && sudo rc-admin update`.

## 12. Przeprowadzka na inny serwer

Żeby aplikacje nie zauważyły zmiany (te same ID, ten sam klucz serwera):

1. Na starym serwerze: `sudo rc-admin backup` i pobierz kopię (rozdział 10).
2. Na nowym: kroki 3–6 (instalacja).
3. Prześlij kopię na nowy serwer i odtwórz ją:
   ```sh
   sudo systemctl stop remoteconn-server
   sudo tar -xzf remoteconn-backup-*.tar.gz -C /
   sudo chown -R remoteconn:remoteconn /var/lib/remoteconn
   sudo systemctl start remoteconn-server
   sudo rc-admin status          # odcisk musi być taki sam jak na starym serwerze
   ```
4. Zmień rekord DNS (krok 2) albo adres w aplikacjach.

## 13. Odinstalowanie

```sh
sudo bash ./deploy/install.sh --uninstall            # usuwa usługę, dane zostają
sudo bash ./deploy/install.sh --uninstall --purge    # usuwa też dane, klucze i użytkownika
```

## 14. Problemy i rozwiązania

| Objaw | Przyczyna i rozwiązanie |
|---|---|
| `install.sh: Permission denied` | archiwum z Windows nie zachowuje uprawnień; uruchamiaj przez `sudo bash ./deploy/install.sh` |
| `$'\r': command not found` | końce linii z Windows; napraw: `sed -i 's/\r$//' deploy/install.sh deploy/rc-admin` |
| Kompilacja przerwana (`Killed`) | za mało RAM-u; sprawdź `free -h`, dodaj swap albo użyj większego VPS-a |
| „Serwer ID jest nieosiągalny” w aplikacji | otwórz UDP 21116 w panelu dostawcy (krok 5); `sudo rc-admin status` |
| „Serwer ID odrzucił klucz dostępu” | porównaj z `sudo rc-admin key show` |
| „Klucz serwera ID jest inny…” | serwer reinstalowany bez kopii; jeśli to Ty: „Zapomnij klucz serwera” w Ustawienia → Sieć; jeśli nie, nie łącz się i sprawdź, kto przejął adres |
| ID się nie pojawia, status „offline” | najedź na status w aplikacji, żeby zobaczyć przyczynę; sprawdź adres i klucz |
| Zawsze „Relay” | normalne przy NAT symetrycznym, CGNAT i w sieciach komórkowych; działa przez serwer |
| Usługa nie startuje | `sudo rc-admin logs`; najczęściej port zajęty (`sudo ss -ulpn \| grep 21116`, dla panelu `sudo ss -tlpn \| grep 8080`) |
| Panel: „Nieznany host” | wchodź przez `http://localhost:8080` (tunel SSH), nie przez adres IP serwera |
| Panel: „Zbyt wiele nieudanych prób” | odczekaj 15 minut; hasło zmienisz przez `sudo rc-admin panel user passwd admin` |
| Panel: zgubiony telefon z 2FA | `sudo rc-admin panel user totp-off admin`, potem włącz 2FA ponownie |
| „Połącz” w panelu nic nie robi | aplikacja RemoteConn musi być zainstalowana i choć raz uruchomiona na tym komputerze (rejestruje wtedy linki `remoteconn://`) |
| Zablokowałeś sobie SSH | użyj konsoli awaryjnej w panelu dostawcy i usuń `/etc/ssh/sshd_config.d/90-remoteconn-hardening.conf` |

## 15. Ściąga

| Cel | Polecenie |
|---|---|
| Instalacja | `sudo bash ./deploy/install.sh --harden-ssh --fail2ban --auto-updates` |
| Dane dla klientów | `sudo cat /root/remoteconn-credentials.txt` |
| Stan | `sudo rc-admin status` |
| Dziennik | `sudo rc-admin logs -f` |
| Urządzenia | `sudo rc-admin devices` |
| Blokada | `sudo rc-admin block ip|net|device <wartość>` |
| Zdjęcie blokady | `sudo rc-admin unblock <wartość>` |
| Nowy klucz | `sudo rc-admin key rotate` |
| Odcisk serwera | `sudo rc-admin fingerprint` |
| Kopia | `sudo rc-admin backup` |
| Aktualizacja | `sudo rc-admin update` |
| Konto panelu WWW | `sudo rc-admin panel user add admin`, 2FA: `sudo rc-admin panel user totp admin` |
| Tunel do panelu | `ssh -N -L 8080:127.0.0.1:8080 admin@<IP-serwera>` → http://localhost:8080 |
| Zaproszenie na konto | `sudo rc-admin account invite "opis"` |
| Konta | `sudo rc-admin account list` |
| Pomoc | `sudo rc-admin help` |

| Plik | Zawartość |
|---|---|
| `/etc/remoteconn/server.env` | konfiguracja i klucz dostępu (tylko root) |
| `/var/lib/remoteconn/` | rejestr urządzeń, certyfikat, klucz serwera, lista blokad, konta i dziennik panelu |
| `/var/log/remoteconn-admin.log` | dziennik działań administratora |
| `/root/remoteconn-credentials.txt` | adres, klucz i odcisk dla klientów, instrukcja panelu |
