"use strict";

// Admin panel client. All text from the server goes through textContent,
// never innerHTML.

const $ = (sel) => document.querySelector(sel);
let csrf = "";
/** The main administrator sees and installs server updates. */
let isOwner = false;
let currentTab = "overview";
let refreshTimer = null;

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value);
  }
  for (const child of children) {
    if (child == null) continue;
    node.append(child instanceof Node ? child : String(child));
  }
  return node;
}

async function api(path, body) {
  const options = { credentials: "same-origin", headers: {} };
  if (body !== undefined) {
    options.method = "POST";
    options.headers["Content-Type"] = "application/json";
    options.headers["X-RC-CSRF"] = csrf;
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  let data = {};
  try { data = await response.json(); } catch { /* empty body */ }
  if (response.status === 401 && path !== "/api/login") {
    showLogin();
    throw new Error(data.error || "Sesja wygasła");
  }
  if (!response.ok) throw new Error(data.error || `Błąd ${response.status}`);
  return data;
}

function toast(text, isError = false) {
  const node = $("#toast");
  node.textContent = text;
  node.className = isError ? "error" : "";
  node.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { node.hidden = true; }, 4000);
}

const formatId = (id) => id.replace(/(\d{3})(\d{3})(\d{3})/, "$1 $2 $3");

// Polish plural: 1 urządzenie, 2–4 urządzenia, 5+ urządzeń (but 22 urządzenia).
function plural(n, one, few, many) {
  if (n === 1) return one;
  const last = n % 10, lastTwo = n % 100;
  return last >= 2 && last <= 4 && (lastTwo < 12 || lastTwo > 14) ? few : many;
}

function formatTime(unix) {
  if (!unix) return "—";
  return new Date(unix * 1000).toLocaleString("pl-PL");
}

function formatDuration(seconds) {
  seconds = Math.max(0, Math.floor(seconds));
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d) return `${d} d ${h} h`;
  if (h) return `${h} h ${m} min`;
  if (m) return `${m} min`;
  return `${seconds} s`;
}

function formatBytes(n) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
}

function fillTable(selector, rows, emptyText, columns) {
  const body = $(`${selector} tbody`);
  body.replaceChildren();
  if (!rows.length) {
    body.append(el("tr", {}, el("td", { colspan: columns, class: "empty" }, emptyText)));
    return;
  }
  for (const row of rows) body.append(row);
}

// ---------- views ----------

function showLogin() {
  stopRefresh();
  csrf = "";
  $("#app-view").hidden = true;
  $("#login-view").hidden = false;
  $("#login-form [name=user]").focus();
}

function showApp(user) {
  $("#who").textContent = user;
  $("#login-view").hidden = true;
  $("#app-view").hidden = false;
  selectTab(currentTab);
}

function selectTab(name) {
  currentTab = name;
  for (const button of document.querySelectorAll("#tabs [role=tab]")) {
    button.setAttribute("aria-selected", String(button.dataset.tab === name));
  }
  for (const section of document.querySelectorAll(".tab")) {
    section.hidden = section.id !== `tab-${name}`;
  }
  refresh();
  stopRefresh();
  refreshTimer = setInterval(refresh, 5000);
}

function stopRefresh() {
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = null;
}

async function refresh() {
  if (document.hidden) return;
  try {
    await loaders[currentTab]();
  } catch (e) {
    if (csrf) toast(e.message, true);
  }
}

const loaders = {
  async overview() {
    const o = await api("/api/overview");
    const stat = (label, value, hint) =>
      el("div", { class: "card stat" },
        el("div", { class: "stat-value" }, value),
        el("div", { class: "stat-label" }, label),
        hint ? el("div", { class: "muted small" }, hint) : null);
    $("#stats").replaceChildren(
      stat("Online", o.online, `z ${o.registered} zarejestrowanych`),
      stat("Sesje relay", o.relays_active, `limit ${o.max_relays}`),
      stat("Przesłano przez relay", formatBytes(o.relay_bytes), "od startu"),
      stat("Czas działania", formatDuration(o.now_unix - o.started_unix), `od ${formatTime(o.started_unix)}`),
    );
    const kv = (k, v, cls) => [el("dt", {}, k), el("dd", cls ? { class: cls } : {}, v)];
    $("#server-info").replaceChildren(
      ...kv("Wersja", o.version),
      ...kv("Odcisk certyfikatu", o.fingerprint, "mono"),
      ...kv("Pełny odcisk", o.fingerprint_full, "mono small"),
      ...kv("Klucz dostępu", o.access_key_set ? "ustawiony (klienci muszą go podać)" : "BRAK – serwer otwarty dla każdego", o.access_key_set ? "" : "warn"),
      ...kv("Wpisy na liście blokad", o.blocklist),
      ...kv("Konta", `${o.accounts} (zakładanie: ${SIGNUP[o.signup] || o.signup})`),
    );
    await renderUpdate();
  },

  async devices() {
    const q = encodeURIComponent($("#device-search").value.trim());
    const online = $("#device-online").checked;
    const data = await api(`/api/devices?q=${q}&online=${online}`);
    const shown = data.devices.length;
    $("#device-count").textContent = data.matched > shown
      ? `pokazano ${shown} z ${data.matched}`
      : `${data.matched} ${plural(data.matched, "urządzenie", "urządzenia", "urządzeń")}`;
    const now = Date.now() / 1000;
    fillTable("#devices-table", data.devices.map((d) => {
      const actions = el("td", { class: "actions" });
      if (d.online && !d.blocked) {
        actions.append(el("a", {
          class: "button primary",
          href: `remoteconn://connect?id=${encodeURIComponent(d.id)}`,
          title: "Otwiera aplikację RemoteConn z tym ID",
        }, "Połącz"));
        actions.append(el("button", { class: "ghost", onclick: () => kick(d.id) }, "Rozłącz"));
      }
      actions.append(d.blocked
        ? el("button", { class: "ghost", onclick: () => unblock(`device ${d.id}`) }, "Odblokuj")
        : el("button", { class: "ghost danger-text", onclick: () => block("device", d.id) }, "Zablokuj"));
      return el("tr", {},
        el("td", { class: "mono" }, formatId(d.id)),
        el("td", {}, d.name || "—"),
        el("td", {}, d.account || "—"),
        el("td", {}, d.blocked
          ? el("span", { class: "badge red" }, "zablokowane")
          : el("span", { class: d.online ? "badge green" : "badge" }, d.online ? "online" : "offline")),
        el("td", { class: "mono small" }, d.observed || "—"),
        el("td", {}, d.since_unix ? `${formatDuration(now - d.since_unix)} temu` : "—"),
        actions);
    }), online ? "Żadne urządzenie nie jest teraz online." : "Brak urządzeń.", 7);
  },

  async accounts() {
    const [data, inv] = await Promise.all([api("/api/accounts"), api("/api/invites")]);
    $("#signup-mode").textContent = `Zakładanie kont: ${SIGNUP[data.signup] || data.signup} (zmienna RC_ACCOUNTS).`;
    $("#invite-form").hidden = data.signup !== "invite";
    fillTable("#invites-table", inv.invites.map((i) => el("tr", {},
      el("td", {}, i.note || el("span", { class: "muted" }, `#${i.key}`)),
      el("td", {}, formatTime(i.created_unix)),
      el("td", {}, formatTime(i.expires_unix)),
      el("td", { class: "actions" },
        el("button", { class: "ghost", onclick: () => act(api(`/api/invites/${i.key}/delete`, {}), "Usunięto zaproszenie") }, "Usuń")),
    )), "Brak aktywnych zaproszeń.", 4);

    const list = $("#accounts-list");
    list.replaceChildren();
    if (!data.accounts.length) {
      list.append(el("div", { class: "card empty" },
        "Nie ma jeszcze kont. Utwórz zaproszenie i przekaż kod użytkownikowi: wpisze go w aplikacji (Ustawienia → Konto → Nowe konto)."));
    }
    for (const a of data.accounts) {
      const rows = a.devices.length
        ? a.devices.map((d) => el("tr", {},
          el("td", {}, d.name || "—"),
          el("td", { class: "mono" }, d.device_id ? formatId(d.device_id) : "—"),
          el("td", {}, el("span", { class: d.online ? "badge green" : "badge" }, d.online ? "online" : "offline")),
          el("td", {}, formatTime(d.added_unix)),
          el("td", { class: "actions" },
            el("button", { class: "ghost danger-text", onclick: () => revokeDevice(a.name, d) }, "Odbierz dostęp")),
        ))
        : [el("tr", {}, el("td", { colspan: 5, class: "empty" }, "Brak urządzeń."))];
      const devices = el("table", {},
        el("thead", {}, el("tr", {},
          el("th", {}, "Urządzenie"), el("th", {}, "ID"), el("th", {}, "Stan"), el("th", {}, "Dodane"), el("th", {}))),
        el("tbody", {}, ...rows));
      const revoked = a.revoked ? ` · odebrane urządzenia: ${a.revoked}` : "";
      list.append(el("div", { class: "card account-card" },
        el("div", { class: "account-head" },
          el("div", {},
            el("strong", {}, a.display_name), " ", el("span", { class: "muted" }, a.name), " ",
            a.disabled ? el("span", { class: "badge red" }, "zablokowane") : null,
            el("div", { class: "muted small" }, `założone ${formatTime(a.created_unix)}${revoked}`)),
          el("div", { class: "actions" },
            a.disabled
              ? el("button", { class: "ghost", onclick: () => act(api(`/api/accounts/${encodeURIComponent(a.name)}/enable`, {}), `Odblokowano ${a.name}`) }, "Odblokuj")
              : el("button", { class: "ghost danger-text", onclick: () => accountAction(a.name, "disable",
                `Zablokować konto ${a.name}? Jego urządzenia przestaną łączyć się bez hasła.`) }, "Zablokuj"),
            el("button", { class: "ghost danger-text", onclick: () => accountAction(a.name, "delete",
              `Usunąć konto ${a.name}? Tego nie da się cofnąć.`) }, "Usuń"))),
        el("div", { class: "table-card" }, devices)));
    }
  },

  async relays() {
    const data = await api("/api/relays");
    const now = Date.now() / 1000;
    fillTable("#relays-table", data.relays.map((r) => el("tr", {},
      el("td", {}, r.id),
      el("td", { class: "mono small" }, r.a),
      el("td", { class: "mono small" }, r.b),
      el("td", {}, formatDuration(now - r.since_unix)),
      el("td", {}, formatBytes(r.bytes)),
      el("td", { class: "actions" },
        el("button", { class: "ghost danger-text", onclick: () => closeRelay(r.id) }, "Zakończ")),
    )), "Brak aktywnych sesji przez relay.", 6);
  },

  async blocklist() {
    const data = await api("/api/blocklist");
    const names = { device: "Urządzenie", ip: "Adres IP", net: "Sieć" };
    fillTable("#block-table", data.entries.map((e) => el("tr", {},
      el("td", {}, names[e.kind] || e.kind),
      el("td", { class: "mono" }, e.kind === "device" ? formatId(e.value) : e.value),
      el("td", { class: "actions" },
        el("button", { class: "ghost", onclick: () => unblock(e.line) }, "Usuń")),
    )), "Lista blokad jest pusta.", 3);
    const errors = $("#block-errors");
    errors.hidden = !data.errors.length;
    errors.textContent = data.errors.length
      ? `Pominięte błędne linie w blocklist.txt: ${data.errors.join("; ")}` : "";
  },

  async events() {
    const data = await api("/api/events?limit=300");
    const kinds = {
      host_online: ["online", "green"], host_offline: ["offline", ""],
      relay_request: ["relay", "blue"], relay_start: ["relay start", "blue"],
      relay_end: ["relay koniec", ""], blocked: ["blokada", "red"], admin: ["admin", "amber"],
    };
    fillTable("#events-table", data.events.map((e) => {
      const [label, color] = kinds[e.kind] || [e.kind, ""];
      return el("tr", {},
        el("td", { class: "nowrap" }, formatTime(e.at_unix)),
        el("td", {}, el("span", { class: `badge ${color}` }, label)),
        el("td", {}, e.text));
    }), "Brak zdarzeń od startu serwera.", 3);
  },

  async audit() {
    const data = await api("/api/audit?limit=300");
    $("#audit-lines").textContent = data.lines.length ? data.lines.join("\n") : "Brak wpisów.";
  },
};

// ---------- actions ----------

async function act(promise, message) {
  try {
    await promise;
    toast(message);
  } catch (e) {
    toast(e.message, true);
  }
  refresh();
}

const SIGNUP = { invite: "na zaproszenie", open: "otwarte dla każdego", off: "wyłączone" };

// ---------- server updates (main administrator only) ----------

const UPDATE_STATE = {
  requested: "zlecona, czeka na uruchomienie",
  running: "w toku (budowanie i restart, kilka minut)",
  done: "zakończona",
  failed: "nieudana, przywrócono poprzednią wersję",
};

async function renderUpdate() {
  const card = $("#update-card");
  if (!isOwner) {
    card.hidden = true;
    return;
  }
  const u = await api("/api/update");
  const rows = [
    el("h2", {}, "Aktualizacje serwera"),
    el("p", {}, `Zainstalowana wersja: `, el("strong", {}, `v${u.current}`)),
  ];
  const a = u.available;
  if (!a) {
    rows.push(el("p", { class: "muted small" }, "Serwer jeszcze nie sprawdzał wydań (raz dziennie)."));
  } else if (a.error) {
    rows.push(el("p", { class: "error small" }, `Ostatnie sprawdzanie nie powiodło się: ${a.error}`));
  } else {
    rows.push(el("p", { class: "muted small" }, `Ostatnie sprawdzenie: ${formatTime(a.checked_unix)}`));
  }
  const s = u.status;
  if (s && s.state) {
    const cls = s.state === "failed" ? "error" : s.state === "done" ? "ok-text" : "";
    rows.push(el("p", { class: cls }, `Aktualizacja do ${s.version}: ${UPDATE_STATE[s.state] || s.state}`,
      s.message ? el("span", { class: "muted small" }, ` — ${s.message}`) : null));
    if (s.state === "failed" && s.log) rows.push(el("pre", { class: "log" }, s.log));
  }
  const busy = u.pending || (s && (s.state === "requested" || s.state === "running"));
  if (u.update && !busy) {
    rows.push(el("p", {}, el("strong", {}, `Dostępna nowa wersja: ${u.update}`)));
    if (a && a.notes) rows.push(el("pre", { class: "log" }, a.notes));
    if (u.totp_enabled) {
      rows.push(el("button", { class: "primary", onclick: () => startUpdate(u.update) }, `Zaktualizuj do ${u.update}`));
      rows.push(el("p", { class: "muted small" },
        "Serwer zbuduje nową wersję i uruchomi się ponownie (trwające połączenia przez relay zostaną przerwane). "
        + "Jeśli nowa wersja nie wystartuje, wróci poprzednia."));
    } else {
      rows.push(el("p", { class: "warn" },
        "Instalacja aktualizacji wymaga 2FA na Twoim koncie: sudo rc-admin panel user totp <nazwa>"));
    }
  } else if (!u.update && a && !a.error) {
    rows.push(el("p", { class: "ok-text" }, "Masz najnowszą wersję."));
  }
  card.replaceChildren(...rows);
  card.hidden = false;
}

function startUpdate(version) {
  if (!confirm(`Zaktualizować serwer do ${version}? Serwer uruchomi się ponownie.`)) return;
  act(api("/api/update", { version }), `Zlecono aktualizację do ${version}`);
}

function accountAction(name, action, question) {
  if (!confirm(question)) return;
  act(api(`/api/accounts/${encodeURIComponent(name)}/${action}`, {}),
    action === "delete" ? `Usunięto ${name}` : `Zablokowano ${name}`);
}

function revokeDevice(name, device) {
  if (!confirm(`Odebrać dostęp urządzeniu „${device.name}” na koncie ${name}? Komputery konta przestaną je wpuszczać bez hasła.`)) return;
  act(api(`/api/accounts/${encodeURIComponent(name)}/revoke`, { public_key: device.public_key }), "Odebrano dostęp");
}

function kick(id) {
  act(api(`/api/devices/${id}/kick`, {}), `Rozłączono ${formatId(id)} (połączy się ponownie, jeśli nie jest zablokowane)`);
}

function block(kind, value) {
  const label = kind === "device" ? formatId(value) : value;
  if (!confirm(`Zablokować ${label}? Zablokowane urządzenie zostanie od razu rozłączone.`)) return;
  act(api("/api/block", { kind, value }), `Zablokowano ${label}`);
}

function unblock(line) {
  act(api("/api/unblock", { line }), "Usunięto z listy blokad");
}

function closeRelay(id) {
  if (!confirm(`Zakończyć sesję relay #${id}? Obie strony zostaną rozłączone.`)) return;
  act(api(`/api/relays/${id}/close`, {}), `Zakończono sesję #${id}`);
}

// ---------- wiring ----------

document.addEventListener("DOMContentLoaded", async () => {
  $("#login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.target;
    const error = $("#login-error");
    const button = form.querySelector("button");
    error.hidden = true;
    button.disabled = true;
    try {
      const data = await api("/api/login", {
        user: form.user.value.trim(),
        password: form.password.value,
        code: form.code.value.replace(/\s/g, ""),
      });
      csrf = data.csrf;
      isOwner = !!data.owner;
      form.password.value = "";
      form.code.value = "";
      showApp(data.user);
    } catch (e) {
      error.textContent = e.message;
      error.hidden = false;
    } finally {
      button.disabled = false;
    }
  });

  $("#logout").addEventListener("click", async () => {
    try { await api("/api/logout", {}); } catch { /* already gone */ }
    showLogin();
  });

  for (const button of document.querySelectorAll("#tabs [role=tab]")) {
    button.addEventListener("click", () => selectTab(button.dataset.tab));
  }

  let searchTimer = null;
  $("#device-search").addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(refresh, 250);
  });
  $("#device-online").addEventListener("change", refresh);

  $("#invite-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const note = event.target.elements.namedItem("note");
    try {
      const data = await api("/api/invites", { note: note.value.trim() });
      note.value = "";
      const box = $("#invite-code");
      box.replaceChildren(
        el("div", {}, "Kod zaproszenia (ważny 7 dni, jednorazowy). Przekaż go użytkownikowi; drugi raz go nie zobaczysz:"),
        el("div", { class: "invite-code mono" }, data.code));
      box.hidden = false;
      refresh();
    } catch (e) {
      toast(e.message, true);
    }
  });

  $("#block-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const fields = event.target.elements;
    const input = fields.namedItem("value");
    const value = input.value.trim();
    if (!value) return;
    input.value = "";
    block(fields.namedItem("kind").value, value);
  });

  document.addEventListener("visibilitychange", () => { if (!document.hidden && csrf) refresh(); });

  try {
    const me = await fetch("/api/me", { credentials: "same-origin" });
    if (me.ok) {
      const data = await me.json();
      csrf = data.csrf;
      isOwner = !!data.owner;
      showApp(data.user);
      return;
    }
  } catch { /* fall through to login */ }
  showLogin();
});
