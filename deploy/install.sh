#!/usr/bin/env bash
# RemoteConn server installer for Linux (Debian/Ubuntu, Fedora/RHEL/Rocky/Alma).
#
# Run from a copy of the repository on the server:
#   sudo bash ./deploy/install.sh                 # install with secure defaults
#   sudo bash ./deploy/install.sh --harden-ssh --fail2ban --auto-updates
#   sudo bash ./deploy/install.sh --update        # rebuild and restart
#   sudo bash ./deploy/install.sh --uninstall [--purge]
#
# What it sets up:
#   - builds rc-server from this repository (Rust toolchain in /opt/remoteconn)
#   - system user "remoteconn" without a shell, data in /var/lib/remoteconn (0700)
#   - random access key in /etc/remoteconn/server.env (root only, 0600)
#   - systemd service with sandboxing (no privileges, read-only system, ...)
#   - firewall: SSH (rate limited) + the server's UDP port
#   - larger UDP buffers for QUIC
#   - rc-admin: root-only admin tool with an audit log
#   - admin web panel on 127.0.0.1 only (reach it through an SSH tunnel)
# Optional admin hardening: key-only SSH, fail2ban, automatic security updates.

set -Eeuo pipefail

# --------------------------------------------------------------------- config
SERVICE=remoteconn-server
SERVICE_USER=remoteconn
INSTALL_ROOT=/opt/remoteconn
CONF_DIR=/etc/remoteconn
ENV_FILE=$CONF_DIR/server.env
INSTALL_CONF=$CONF_DIR/install.conf
DATA_DIR=/var/lib/remoteconn
BIN=/usr/local/bin/rc-server
ADMIN_BIN=/usr/local/sbin/rc-admin
ADMIN_LOG=/var/log/remoteconn-admin.log
UNIT_FILE=/etc/systemd/system/$SERVICE.service
SYSCTL_FILE=/etc/sysctl.d/90-remoteconn.conf
SSH_DROPIN=/etc/ssh/sshd_config.d/90-remoteconn-hardening.conf
F2B_JAIL=/etc/fail2ban/jail.d/remoteconn-sshd.local
CREDENTIALS=/root/remoteconn-credentials.txt
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

PORT=21116
ACCESS_KEY=""
RELAY_ADDR=""
MAX_RELAYS=200
MAX_CONN=32
ADMIN_PORT=""
NO_PANEL=0
FIREWALL=1
HARDEN_SSH=0
FAIL2BAN=0
AUTO_UPDATES=0
ASSUME_YES=0
MODE=install
PURGE=0

# -------------------------------------------------------------------- helpers
if [[ -t 1 ]]; then
    C_OK=$'\e[32m' C_WARN=$'\e[33m' C_ERR=$'\e[31m' C_B=$'\e[1m' C_0=$'\e[0m'
else
    C_OK="" C_WARN="" C_ERR="" C_B="" C_0=""
fi
info() { echo "${C_B}==>${C_0} $*"; }
ok()   { echo "${C_OK}  ✓${C_0} $*"; }
warn() { echo "${C_WARN}  !${C_0} $*" >&2; }
die()  { echo "${C_ERR}BŁĄD:${C_0} $*" >&2; exit 1; }
trap 'die "przerwano w linii $LINENO (polecenie: $BASH_COMMAND)"' ERR

usage() {
    cat <<EOF
Instalator serwera RemoteConn (rendezvous + relay).

Użycie: sudo $0 [opcje]

  --port PORT            port UDP serwera (domyślnie 21116)
  --access-key KLUCZ     klucz dostępu dla klientów (domyślnie losowy)
  --relay-addr HOST:PORT ogłaszaj osobny relay zamiast tego serwera
  --max-relays N         limit równoczesnych sesji relay (domyślnie 200)
  --max-conn N           limit połączeń na IP / sieć IPv6 /64 (domyślnie 32)
  --admin-port PORT      port panelu WWW, tylko na 127.0.0.1 (domyślnie 8080)
  --no-panel             bez panelu WWW
  --no-firewall          nie zmieniaj zapory
  --harden-ssh           SSH tylko na klucze, bez logowania roota hasłem
  --fail2ban             fail2ban dla SSH (blokuje zgadywanie haseł)
  --auto-updates         automatyczne aktualizacje bezpieczeństwa systemu
  --yes                  bez pytań (instalacja nienadzorowana)
  --update               przebuduj z repozytorium i zrestartuj usługę
  --uninstall            usuń usługę (dane zostają; z --purge też dane)
  -h, --help             ta pomoc
EOF
}

confirm() {
    [[ $ASSUME_YES == 1 ]] && return 0
    local answer
    read -r -p "$1 [t/N] " answer
    [[ $answer =~ ^[tTyY]$ ]]
}

# ---------------------------------------------------------------------- args
while [[ $# -gt 0 ]]; do
    case $1 in
        --port) PORT=${2:?}; shift 2 ;;
        --access-key) ACCESS_KEY=${2:?}; shift 2 ;;
        --relay-addr) RELAY_ADDR=${2:?}; shift 2 ;;
        --max-relays) MAX_RELAYS=${2:?}; shift 2 ;;
        --max-conn) MAX_CONN=${2:?}; shift 2 ;;
        --admin-port) ADMIN_PORT=${2:?}; shift 2 ;;
        --no-panel) NO_PANEL=1; shift ;;
        --no-firewall) FIREWALL=0; shift ;;
        --harden-ssh) HARDEN_SSH=1; shift ;;
        --fail2ban) FAIL2BAN=1; shift ;;
        --auto-updates) AUTO_UPDATES=1; shift ;;
        --yes|-y) ASSUME_YES=1; shift ;;
        --update) MODE=update; shift ;;
        --uninstall) MODE=uninstall; shift ;;
        --purge) PURGE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage; die "nieznana opcja: $1" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "uruchom jako root (sudo $0 ...)"
if ! [[ $PORT =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    die "nieprawidłowy port: $PORT"
fi
[[ $MAX_RELAYS =~ ^[0-9]+$ && $MAX_CONN =~ ^[0-9]+$ ]] || die "limity muszą być liczbami"
if [[ -n $ADMIN_PORT ]] && { ! [[ $ADMIN_PORT =~ ^[0-9]+$ ]] || (( ADMIN_PORT < 1 || ADMIN_PORT > 65535 )); }; then
    die "nieprawidłowy port panelu: $ADMIN_PORT"
fi
if [[ -n $ACCESS_KEY ]]; then
    [[ ${#ACCESS_KEY} -ge 16 ]] || die "klucz dostępu musi mieć co najmniej 16 znaków"
    [[ $ACCESS_KEY =~ ^[A-Za-z0-9._~-]+$ ]] || die "klucz dostępu: dozwolone litery, cyfry i . _ ~ -"
fi
command -v systemctl >/dev/null || die "wymagany systemd"

# ------------------------------------------------------------------- distro
PKG=""
if command -v apt-get >/dev/null; then PKG=apt
elif command -v dnf >/dev/null; then PKG=dnf
else die "obsługiwane są systemy z apt (Debian/Ubuntu) albo dnf (Fedora/RHEL)"
fi

pkg_install() {
    case $PKG in
        apt) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null ;;
        dnf) dnf install -y -q "$@" >/dev/null ;;
    esac
}

# ----------------------------------------------------------------- uninstall
uninstall() {
    info "Usuwanie serwera RemoteConn"
    systemctl disable --now "$SERVICE" 2>/dev/null || true
    rm -f "$UNIT_FILE" "$BIN" "$ADMIN_BIN" "$SYSCTL_FILE"
    systemctl daemon-reload
    if command -v ufw >/dev/null; then
        local port
        port=$(grep -oP '^RC_BIND=.*:\K[0-9]+' "$ENV_FILE" 2>/dev/null || echo "$PORT")
        ufw delete allow "$port/udp" >/dev/null 2>&1 || true
    fi
    if [[ $PURGE == 1 ]]; then
        confirm "Usunąć też dane (rejestr urządzeń, certyfikat, klucz)?" || die "anulowano"
        rm -rf "$DATA_DIR" "$CONF_DIR" "$INSTALL_ROOT" "$CREDENTIALS"
        userdel "$SERVICE_USER" 2>/dev/null || true
        ok "usunięto dane i użytkownika $SERVICE_USER"
    else
        ok "dane zostały w $DATA_DIR i $CONF_DIR (usuń je opcją --purge)"
    fi
    ok "usługa usunięta"
}

# --------------------------------------------------------------------- build
ensure_build_memory() {
    # Compiling needs ~1.5 GB; small VPSes get a temporary swap file.
    local mem_kb swap_kb
    mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    swap_kb=$(awk '/SwapTotal/ {print $2}' /proc/meminfo)
    if (( mem_kb + swap_kb < 2000000 )) && [[ ! -e /swapfile-remoteconn-build ]]; then
        warn "mało pamięci RAM ($((mem_kb / 1024)) MB): tymczasowy swap 2 GB na czas kompilacji"
        fallocate -l 2G /swapfile-remoteconn-build 2>/dev/null \
            || dd if=/dev/zero of=/swapfile-remoteconn-build bs=1M count=2048 status=none
        chmod 600 /swapfile-remoteconn-build
        mkswap /swapfile-remoteconn-build >/dev/null
        swapon /swapfile-remoteconn-build
        TEMP_SWAP=1
    fi
}

remove_build_swap() {
    if [[ ${TEMP_SWAP:-0} == 1 ]]; then
        swapoff /swapfile-remoteconn-build || true
        rm -f /swapfile-remoteconn-build
    fi
}

build_server() {
    [[ -f $REPO_DIR/Cargo.toml && -d $REPO_DIR/rc-server ]] \
        || die "nie znaleziono repozytorium RemoteConn w $REPO_DIR (uruchom skrypt z kopii repozytorium)"

    info "Pakiety do kompilacji"
    case $PKG in
        apt) apt-get update -qq >/dev/null
             pkg_install build-essential pkg-config curl ca-certificates ;;
        dnf) pkg_install gcc gcc-c++ make pkgconf-pkg-config curl ca-certificates tar ;;
    esac
    ok "zainstalowane"

    export RUSTUP_HOME=$INSTALL_ROOT/rustup CARGO_HOME=$INSTALL_ROOT/cargo
    export PATH=$CARGO_HOME/bin:$PATH
    if ! command -v cargo >/dev/null; then
        info "Rust (tylko dla RemoteConn, w $INSTALL_ROOT)"
        mkdir -p "$INSTALL_ROOT"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
            | sh -s -- -y --quiet --profile minimal --default-toolchain stable --no-modify-path
    else
        rustup update stable --no-self-update >/dev/null 2>&1 || true
    fi
    ok "$(cargo --version)"

    info "Kompilacja rc-server (kilka minut)"
    ensure_build_memory
    local jobs=""
    (( $(awk '/MemTotal/ {print $2}' /proc/meminfo) < 2000000 )) && jobs="-j 1"
    # shellcheck disable=SC2086
    CARGO_TARGET_DIR=$INSTALL_ROOT/build cargo build --release --locked -p rc-server $jobs \
        --manifest-path "$REPO_DIR/Cargo.toml"
    remove_build_swap
    install -o root -g root -m 0755 "$INSTALL_ROOT/build/release/rc-server" "$BIN"
    ok "zainstalowano $BIN"
}

# -------------------------------------------------------------------- system
create_user() {
    if ! id "$SERVICE_USER" >/dev/null 2>&1; then
        local nologin
        nologin=$(command -v nologin || echo /usr/sbin/nologin)
        useradd --system --home-dir "$DATA_DIR" --no-create-home --shell "$nologin" "$SERVICE_USER"
        ok "użytkownik systemowy $SERVICE_USER (bez powłoki i hasła)"
    fi
    install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0700 "$DATA_DIR"
    install -d -o root -g root -m 0700 "$CONF_DIR"
}

# RC_ADMIN_BIND value: from the options, else kept from an earlier install.
panel_bind() {
    if [[ $NO_PANEL == 1 ]]; then
        echo off
    elif [[ -n $ADMIN_PORT ]]; then
        echo "127.0.0.1:$ADMIN_PORT"
    elif [[ -f $ENV_FILE ]] && grep -q '^RC_ADMIN_BIND=' "$ENV_FILE"; then
        grep -oP '^RC_ADMIN_BIND=\K.*' "$ENV_FILE"
    else
        echo "127.0.0.1:8080"
    fi
}

# Installs from before the panel existed get it (on loopback) when updated.
ensure_panel_config() {
    if ! grep -q '^RC_ADMIN_BIND=' "$ENV_FILE"; then
        printf '# Admin web panel: loopback only, use an SSH tunnel (see rc-admin panel url).\nRC_ADMIN_BIND=127.0.0.1:8080\n' >>"$ENV_FILE"
        ok "panel WWW włączony na 127.0.0.1:8080 (konto: sudo rc-admin panel user add <nazwa>)"
    fi
}

# First install: guided panel setup (administrator account + 2FA) through
# rc-admin, so it is the same flow as `rc-admin panel setup` later.
setup_panel() {
    [[ $(panel_bind) == off ]] && return
    local users
    users=$(runuser -u "$SERVICE_USER" -- env RC_DATA_DIR="$DATA_DIR" "$BIN" panel-user list 2>/dev/null || true)
    [[ -z $users ]] || return 0
    if [[ $ASSUME_YES == 1 || ! -t 0 ]]; then
        warn "panel WWW nie ma jeszcze konta: skonfiguruj je poleceniem sudo rc-admin panel setup"
        return
    fi
    echo
    info "Panel WWW: konto administratora i 2FA"
    if ! "$ADMIN_BIN" panel setup; then
        warn "konfiguracja panelu nie została dokończona; uruchom ponownie: sudo rc-admin panel setup"
    fi
}

write_env() {
    if [[ -f $ENV_FILE && -z $ACCESS_KEY ]]; then
        # Reinstall: keep the existing key so clients keep working.
        ACCESS_KEY=$(grep -oP '^RC_ACCESS_KEY=\K.*' "$ENV_FILE" || true)
    fi
    [[ -n $ACCESS_KEY ]] || ACCESS_KEY=$("$BIN" gen-key)
    local admin_bind accounts
    admin_bind=$(panel_bind)
    accounts=invite
    if [[ -f $ENV_FILE ]] && grep -q '^RC_ACCOUNTS=' "$ENV_FILE"; then
        accounts=$(grep -oP '^RC_ACCOUNTS=\K.*' "$ENV_FILE")
    fi
    umask 077
    cat >"$ENV_FILE" <<EOF
# RemoteConn server configuration (read by systemd as root; mode 0600).
# Change with: rc-admin key rotate | rc-admin config
RC_BIND=0.0.0.0:$PORT
RC_DATA_DIR=$DATA_DIR
RC_ACCESS_KEY=$ACCESS_KEY
RC_RELAY_ADDR=$RELAY_ADDR
RC_MAX_RELAYS=$MAX_RELAYS
RC_MAX_CONN_PER_CLIENT=$MAX_CONN
# Admin web panel: loopback only, use an SSH tunnel (see rc-admin panel url).
RC_ADMIN_BIND=$admin_bind
# Who may create user accounts: invite (codes from the panel), open, off.
RC_ACCOUNTS=$accounts
RUST_LOG=info
EOF
    chown root:root "$ENV_FILE"
    chmod 0600 "$ENV_FILE"
    cat >"$INSTALL_CONF" <<EOF
REPO_DIR=$REPO_DIR
INSTALLED=$(date -Is)
EOF
    chmod 0600 "$INSTALL_CONF"
    umask 022
    ok "konfiguracja w $ENV_FILE (tylko root)"
}

write_unit() {
    local caps=""
    if (( PORT < 1024 )); then
        caps=$'AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE'
    else
        caps=$'AmbientCapabilities=\nCapabilityBoundingSet='
    fi
    cat >"$UNIT_FILE" <<EOF
[Unit]
Description=RemoteConn rendezvous and relay server
Documentation=file://$REPO_DIR/docs/SERWER.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
EnvironmentFile=$ENV_FILE
ExecStart=$BIN run
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
TasksMax=4096

# --- sandbox: the server only needs UDP sockets and its data directory ---
$caps
NoNewPrivileges=yes
UMask=0077
ProtectSystem=strict
ReadWritePaths=$DATA_DIR
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    ok "usługa $SERVICE (z izolacją systemd)"
}

tune_udp() {
    cat >"$SYSCTL_FILE" <<EOF
# Larger UDP buffers for QUIC (RemoteConn video and relay traffic).
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
EOF
    sysctl -q --load "$SYSCTL_FILE" || warn "nie udało się zastosować $SYSCTL_FILE"
    ok "bufory UDP dla QUIC"
}

ssh_ports() {
    local ports
    ports=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' || true)
    echo "${ports:-22}"
}

setup_firewall() {
    [[ $FIREWALL == 1 ]] || { warn "pominięto zaporę (--no-firewall): otwórz UDP $PORT ręcznie"; return; }
    info "Zapora"
    if command -v firewall-cmd >/dev/null && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port="$PORT/udp" >/dev/null
        firewall-cmd --permanent --add-service=ssh >/dev/null
        firewall-cmd --reload >/dev/null
        ok "firewalld: SSH + $PORT/udp"
        return
    fi
    if [[ $PKG == dnf ]] && ! command -v ufw >/dev/null; then
        pkg_install firewalld
        systemctl enable --now firewalld >/dev/null
        firewall-cmd --permanent --add-service=ssh >/dev/null
        firewall-cmd --permanent --add-port="$PORT/udp" >/dev/null
        firewall-cmd --reload >/dev/null
        ok "firewalld włączony: SSH + $PORT/udp"
        return
    fi
    command -v ufw >/dev/null || pkg_install ufw
    local p
    # SSH first, so enabling the firewall can never lock the admin out.
    for p in $(ssh_ports); do
        ufw limit "$p/tcp" comment 'SSH (rate limited)' >/dev/null
    done
    ufw allow "$PORT/udp" comment 'RemoteConn' >/dev/null
    ufw default deny incoming >/dev/null
    ufw default allow outgoing >/dev/null
    ufw --force enable >/dev/null
    ok "ufw: SSH (z limitem prób) port(y) $(ssh_ports | tr '\n' ' ')+ $PORT/udp, reszta zablokowana"
}

# ------------------------------------------------------------ admin hardening
harden_ssh() {
    info "Utwardzanie SSH"
    command -v sshd >/dev/null || { warn "brak sshd, pomijam"; return; }
    # Refuse unless an administrator (root or a sudo/wheel member) can still
    # log in with a key afterwards. Run as root after `sudo -i`, SUDO_USER is
    # empty, so all administrators are checked.
    local admins=() with_keys=() user home
    [[ -n ${SUDO_USER:-} ]] && admins+=("$SUDO_USER")
    admins+=(root)
    for user in $(getent group sudo wheel | cut -d: -f4 | tr ',' ' '); do
        admins+=("$user")
    done
    for user in "${admins[@]}"; do
        home=$(getent passwd "$user" | cut -d: -f6)
        [[ -n $home && -s $home/.ssh/authorized_keys ]] && with_keys+=("$user")
    done
    if (( ${#with_keys[@]} == 0 )); then
        warn "żaden administrator (root ani członek sudo) nie ma klucza SSH - NIE wyłączam haseł (zablokowałbyś sobie dostęp)"
        warn "dodaj klucz (ssh-copy-id użytkownik@serwer) i uruchom ponownie z --harden-ssh"
        return
    fi
    ok "logowanie kluczem SSH mają: $(printf '%s\n' "${with_keys[@]}" | sort -u | tr '\n' ' ')"
    grep -qiE '^\s*Include\s+/etc/ssh/sshd_config.d/' /etc/ssh/sshd_config \
        || { warn "sshd_config nie wczytuje sshd_config.d - pomijam (dodaj ustawienia ręcznie)"; return; }
    mkdir -p /etc/ssh/sshd_config.d
    cat >"$SSH_DROPIN" <<EOF
# Added by the RemoteConn installer (--harden-ssh).
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
EOF
    if ! sshd -t 2>/dev/null; then
        rm -f "$SSH_DROPIN"
        warn "konfiguracja sshd nie przeszła sprawdzenia - wycofano zmiany"
        return
    fi
    systemctl reload ssh 2>/dev/null || systemctl reload sshd
    ok "SSH: tylko klucze, root bez hasła, max 3 próby (sprawdź logowanie w NOWYM oknie przed zamknięciem obecnego)"
}

setup_fail2ban() {
    info "fail2ban dla SSH"
    if [[ $PKG == dnf ]]; then
        # fail2ban lives in EPEL on RHEL clones (Fedora has it built in).
        pkg_install epel-release 2>/dev/null || true
    fi
    pkg_install fail2ban
    mkdir -p /etc/fail2ban/jail.d
    cat >"$F2B_JAIL" <<EOF
# Added by the RemoteConn installer (--fail2ban).
[sshd]
enabled  = true
backend  = systemd
maxretry = 5
findtime = 10m
bantime  = 1h
bantime.increment = true
EOF
    systemctl enable --now fail2ban >/dev/null
    systemctl restart fail2ban
    ok "fail2ban: 5 nieudanych logowań w 10 min = blokada od 1 h (rośnie przy powtórkach)"
}

setup_auto_updates() {
    info "Automatyczne aktualizacje bezpieczeństwa"
    case $PKG in
        apt)
            pkg_install unattended-upgrades
            cat >/etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
            ;;
        dnf)
            pkg_install dnf-automatic
            if [[ -f /etc/dnf/automatic.conf ]]; then
                sed -i -e 's/^upgrade_type.*/upgrade_type = security/' \
                       -e 's/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf
            fi
            systemctl enable --now dnf-automatic.timer >/dev/null 2>&1 \
                || systemctl enable --now dnf-automatic-install.timer >/dev/null
            ;;
    esac
    ok "włączone"
}

install_admin_tool() {
    install -o root -g root -m 0700 "$SCRIPT_DIR/rc-admin" "$ADMIN_BIN"
    touch "$ADMIN_LOG"
    chown root:root "$ADMIN_LOG"
    chmod 0600 "$ADMIN_LOG"
    ok "narzędzie administratora $ADMIN_BIN (tylko root, dziennik w $ADMIN_LOG)"
}

public_ip() {
    curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null \
        || hostname -I 2>/dev/null | awk '{print $1}'
}

start_service() {
    systemctl enable "$SERVICE" >/dev/null 2>&1
    systemctl restart "$SERVICE"
    sleep 2
    systemctl is-active --quiet "$SERVICE" \
        || { journalctl -u "$SERVICE" -n 30 --no-pager >&2; die "usługa nie wystartowała"; }
    ok "usługa działa"
}

write_credentials() {
    local fp ip
    fp=$(runuser -u "$SERVICE_USER" -- env RC_DATA_DIR="$DATA_DIR" "$BIN" fingerprint | head -n1)
    ip=$(public_ip)
    umask 077
    cat >"$CREDENTIALS" <<EOF
RemoteConn - dane serwera ($(date -Is))

Adres serwera ID:   ${ip:-<adres-serwera>}:$PORT
Klucz dostępu:      $ACCESS_KEY
Odcisk serwera:     $fp

W aplikacji: Ustawienia -> Sieć -> Serwer ID + Klucz dostępu, potem "Testuj".
Odcisk wyświetlony w aplikacji przy teście musi być taki sam jak powyżej.

Administracja:      sudo rc-admin help
EOF
    local bind
    bind=$(panel_bind)
    if [[ $bind != off ]]; then
        cat >>"$CREDENTIALS" <<EOF

Panel WWW (tylko przez tunel SSH):
  1. konto:   sudo rc-admin panel user add admin   (2FA: sudo rc-admin panel user totp admin)
  2. tunel:   ssh -L ${bind##*:}:127.0.0.1:${bind##*:} ${SUDO_USER:-root}@${ip:-<adres-serwera>}
  3. otwórz:  http://localhost:${bind##*:}
EOF
    fi
    umask 022
    echo
    echo "${C_B}Gotowe.${C_0} Dane dla klientów (zapisane też w $CREDENTIALS, tylko root):"
    echo
    sed -n '3,5p' "$CREDENTIALS"
    echo
    echo "Administracja:  sudo rc-admin status | devices | block | key rotate | logs | help"
    [[ $bind == off ]] || echo "Panel WWW:      sudo rc-admin panel url   (instrukcja tunelu SSH)"
}

# ---------------------------------------------------------------------- main
case $MODE in
    uninstall)
        uninstall
        ;;
    update)
        [[ -f $ENV_FILE ]] || die "serwer nie jest zainstalowany"
        PORT=$(grep -oP '^RC_BIND=.*:\K[0-9]+' "$ENV_FILE")
        build_server
        install_admin_tool
        ensure_panel_config
        start_service
        echo "$(date -Is) $(logname 2>/dev/null || echo root) update" >>"$ADMIN_LOG"
        ok "zaktualizowano"
        ;;
    install)
        info "Instalacja serwera RemoteConn z $REPO_DIR (port UDP $PORT)"
        build_server
        create_user
        write_env
        write_unit
        tune_udp
        setup_firewall
        install_admin_tool
        [[ $HARDEN_SSH == 1 ]] && harden_ssh
        [[ $FAIL2BAN == 1 ]] && setup_fail2ban
        [[ $AUTO_UPDATES == 1 ]] && setup_auto_updates
        start_service
        echo "$(date -Is) $(logname 2>/dev/null || echo root) install port=$PORT" >>"$ADMIN_LOG"
        setup_panel
        write_credentials
        if [[ $HARDEN_SSH == 0 || $FAIL2BAN == 0 ]]; then
            echo
            warn "zalecane dla bezpieczeństwa admina: uruchom ponownie z --harden-ssh --fail2ban --auto-updates"
        fi
        ;;
esac
