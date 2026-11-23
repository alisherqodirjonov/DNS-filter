const page = document.body.dataset.page || "login";
let csrf = "";
let me = null;

document.addEventListener("DOMContentLoaded", init);

async function init() {
  if (page === "login") {
    const form = document.querySelector("#login-form");
    form.addEventListener("submit", signIn);
    return;
  }
  try {
    me = await api("/api/v1/me");
  } catch (_err) {
    window.location.assign("/login");
    return;
  }
  csrf = me.csrf_token;
  if (me.must_change_password && page !== "account") {
    window.location.assign("/account");
    return;
  }
  const who = document.querySelector("#who");
  who.textContent = "";
  who.append(el("strong", null, me.username), el("span", null, roleName(me.role)));
  document.querySelector("#sign-out").addEventListener("click", signOut);
  if (me.must_change_password) {
    document.querySelector(".nav").hidden = true;
  } else if (me.role === "admin") {
    document.querySelectorAll("[data-admin]").forEach((node) => {
      node.hidden = false;
    });
  }
  const screens = {
    dashboard: loadDashboard,
    logs: loadLogs,
    rules: loadRules,
    feeds: loadFeeds,
    settings: loadSettings,
    users: loadUsers,
    audit: loadAudit,
    account: loadAccount,
  };
  const load = screens[page] || loadDashboard;
  load();
}

async function signIn(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button");
  const error = document.querySelector("#login-error");
  error.hidden = true;
  button.disabled = true;
  button.textContent = "Signing in…";
  try {
    const result = await api("/api/v1/auth/login", {
      method: "POST",
      json: {
        username: form.username.value,
        password: form.password.value,
      },
    });
    window.location.assign(result.must_change_password ? "/account" : "/dashboard");
  } catch (err) {
    error.hidden = false;
    error.textContent = err.message;
    button.disabled = false;
    button.textContent = "Sign in";
  }
}

async function signOut() {
  try {
    await api("/api/v1/auth/logout", { method: "POST" });
  } catch (_err) {
    /* The cookie is cleared when the request succeeds. A failure still returns to the sign-in page. */
  }
  window.location.assign("/login");
}

/* Overview */

async function loadDashboard() {
  const root = start("Overview");
  const lede = el("p", { className: "lede" }, "");
  root.append(lede);
  const status = el("p", { className: "status" }, "Loading the summary…");
  root.append(status);
  try {
    const data = await api("/api/v1/dashboard/summary");
    status.remove();
    lede.textContent = "Totals for the last " + plural(data.days, "day") + ". " + loggingNote(data.log_mode);
    root.append(cards([
      ["Queries", number(data.total)],
      ["Allowed", number(data.allowed), "allowed"],
      ["Blocked", number(data.blocked), "blocked"],
      ["Block ratio", percent(data.block_ratio)],
      ["Feed names", number(data.feed_domains)],
    ]));
    const split = el("div", { className: "split" });
    split.append(countPanel("Most blocked names", "Name", data.top_blocked_domains, "qname", "Nothing blocked is in the log yet."));
    split.append(countPanel("Clients with the most blocks", "Client", data.top_blocked_clients, "client_ip", "No blocked client is in the log yet."));
    root.append(split);
    const recent = el("section", { className: "panel recent" });
    recent.append(panelHead("Recent queries", el("a", { href: "/logs", className: "panel-link" }, "Open the log")));
    recent.append(eventTable(data.recent_events, data.log_mode === "none"
      ? "Logging is off, so no queries are listed. Turn it on from the Logs page."
      : "No queries yet. Point a test client at this resolver and they will show up here."));
    root.append(recent);
  } catch (err) {
    showError(status, err);
  }
}

function loggingNote(mode) {
  if (mode === "blocked") return "Only blocked queries are kept in the log, so allowed ones are counted here but not listed.";
  if (mode === "none") return "Logging is off: every query is counted, but none are listed.";
  return "The lists below come from the query log.";
}

/* Logs */

const logModes = [
  ["all", "All queries", "Every query is stored with its client, name, and answer."],
  ["blocked", "Blocked only", "Only blocked queries are stored. Allowed ones are still counted on the overview."],
  ["none", "Nothing", "No queries are stored. The overview still counts every one."],
];

async function loadLogs() {
  const root = start("Logs");
  root.append(el("p", { className: "lede" }, "Each row is one query this filter answered. Blocked names were not sent upstream."));
  const modePanel = el("section", { className: "panel mode-panel" });
  root.append(modePanel);

  const form = el("form", { className: "filters" });
  form.append(field("Domain contains", "qname", { placeholder: "example.test" }));
  form.append(selectField("Decision", "decision", [["", "Any decision"], ["ALLOWED", "Allowed"], ["BLOCKED", "Blocked"], ["ERROR", "Error"]]));
  form.append(el("button", { type: "submit", className: "secondary" }, "Apply filter"));
  root.append(form);
  const list = el("div");
  root.append(list);
  let offset = 0;
  const limit = 50;
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    offset = 0;
    render();
  });

  try {
    const current = await api("/api/v1/settings");
    renderModes(modePanel, current);
  } catch (err) {
    modePanel.append(el("p", { className: "status error" }, err.message));
  }
  render();

  async function render() {
    clear(list);
    const status = el("p", { className: "status" }, "Loading the log…");
    list.append(status);
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    const qname = form.qname.value.trim();
    const selected = form.decision.value;
    if (qname) params.set("qname", qname);
    if (selected) params.set("action", selected);
    try {
      const data = await api("/api/v1/events?" + params.toString());
      status.remove();
      list.append(eventTable(data.events, qname || selected ? "No logged queries match this filter." : "The log is empty."));
      const pager = el("div", { className: "pager" });
      const from = data.total === 0 ? 0 : data.offset + 1;
      const to = Math.min(data.offset + data.events.length, data.total);
      pager.append(el("span", null, "Showing " + from + "–" + to + " of " + data.total));
      const prev = el("button", { type: "button", className: "secondary" }, "Previous");
      const next = el("button", { type: "button", className: "secondary" }, "Next");
      prev.disabled = data.offset === 0;
      next.disabled = data.offset + data.events.length >= data.total;
      prev.addEventListener("click", () => { offset = Math.max(0, offset - limit); render(); });
      next.addEventListener("click", () => { offset += limit; render(); });
      pager.append(prev, next);
      list.append(pager);
    } catch (err) {
      showError(status, err);
    }
  }
}

function renderModes(panel, current) {
  clear(panel);
  const admin = me.role === "admin";
  const head = el("div", { className: "panel-head" });
  head.append(el("h2", null, "What gets logged"));
  const saved = el("span", { className: "saved", role: "status" }, "");
  head.append(saved);
  panel.append(head);
  const group = el("div", { className: "modes", role: "radiogroup", "aria-label": "What gets logged" });
  logModes.forEach(([value, title, detail]) => {
    const option = el("label", { className: "mode" });
    const radio = el("input", { type: "radio", name: "log_mode", value: value });
    radio.checked = current.values.log_mode === value;
    radio.disabled = !admin;
    const text = el("span");
    text.append(el("strong", null, title), el("span", null, detail));
    option.append(radio, text);
    group.append(option);
    radio.addEventListener("change", async () => {
      group.querySelectorAll("input").forEach((input) => { input.disabled = true; });
      saved.className = "saved";
      saved.textContent = "Saving…";
      try {
        const next = await api("/api/v1/settings", { method: "PUT", json: { log_mode: value } });
        renderModes(panel, next);
        const note = panel.querySelector(".saved");
        note.textContent = "Saved. This applies to the next query.";
      } catch (err) {
        renderModes(panel, current);
        const note = panel.querySelector(".saved");
        note.className = "saved error";
        note.textContent = err.message;
      }
    });
  });
  panel.append(group);
  const foot = "Rows are kept for " + plural(current.values.retention_days, "day") + ".";
  panel.append(el("p", { className: "panel-foot" }, admin ? foot + " Change that on the Settings page." : foot + " Only an administrator can change what gets logged."));
}

/* Rules */

async function loadRules() {
  const root = start("Rules");
  root.append(el("p", { className: "note" }, "A suffix rule also covers subdomains. An allow rule forwards the name even when a deny rule or a feed would block it."));
  if (me.role === "admin") {
    const form = el("form", { className: "inline-form panel" });
    form.append(el("h2", null, "Add a rule"));
    form.append(field("Domain", "domain", { placeholder: "example.test", required: "" }));
    form.append(selectField("Type", "rule_type", [["deny", "Deny"], ["allow", "Allow"]]));
    form.append(selectField("Match", "match_type", [["exact", "Exact name"], ["suffix", "Name and subdomains"]]));
    form.append(field("Description", "description", { placeholder: "Optional note" }));
    const button = el("button", { type: "submit" }, "Add rule");
    form.append(button);
    const error = el("p", { className: "form-error" }, "");
    form.append(error);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      error.textContent = "";
      button.disabled = true;
      try {
        await api("/api/v1/rules", {
          method: "POST",
          json: {
            domain: form.domain.value,
            rule_type: form.rule_type.value,
            match_type: form.match_type.value,
            description: form.description.value,
          },
        });
        form.reset();
        await loadRules();
      } catch (err) {
        error.textContent = err.message;
        button.disabled = false;
      }
    });
    root.append(form);
  }
  const list = el("div");
  root.append(list);
  const notice = el("p", { className: "form-error" }, "");
  list.append(notice);
  const status = el("p", { className: "status" }, "Loading rules…");
  list.append(status);
  try {
    const data = await api("/api/v1/rules");
    status.remove();
    if (!data.rules.length) {
      list.append(el("p", { className: "status" }, "No manual rules yet. Names that are not on a feed are forwarded."));
      return;
    }
    list.append(table(["Domain", "Type", "Match", "Description", "Added by", ""], data.rules.map((rule) => {
      const cells = [mono(rule.domain), tag(rule.rule_type === "allow" ? "allowed" : "blocked", label(rule.rule_type)), label(rule.match_type), rule.description || "—", rule.created_by];
      if (me.role === "admin") {
        cells.push(dangerButton("Delete", "Delete the rule for " + rule.domain + "?", async () => {
          try {
            await api("/api/v1/rules/" + rule.id, { method: "DELETE" });
            await loadRules();
          } catch (err) {
            notice.textContent = err.message;
          }
        }));
      } else {
        cells.push("—");
      }
      return cells;
    })));
  } catch (err) {
    showError(status, err);
  }
}

/* Feeds */

async function loadFeeds() {
  const root = start("Threat feeds");
  const note = el("p", { className: "note" }, "A failed sync keeps the names from the last successful load.");
  root.append(note);
  const list = el("div");
  if (me.role === "admin") {
    root.append(feedForm(list, note));
  }
  root.append(list);
  await renderFeeds(list, note, "");
}

function feedForm(list, note) {
  const form = el("form", { className: "inline-form panel" });
  form.append(el("h2", null, "Add a feed"));
  form.append(field("Name", "name", { placeholder: "lab-list", required: "" }));
  const source = field("File path or https address", "source", { placeholder: "/srv/lists/lab.txt", required: "" });
  source.className = "wide";
  form.append(source);
  form.append(selectField("Format", "format", [["domains", "One domain per line"], ["hosts", "Hosts file"]]));
  const button = el("button", { type: "submit" }, "Add feed");
  form.append(button);
  const error = el("p", { className: "form-error" }, "");
  form.append(error);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.textContent = "";
    button.disabled = true;
    button.textContent = "Loading…";
    const value = form.source.value.trim();
    const remote = /^https:\/\//i.test(value);
    try {
      const result = await api("/api/v1/feeds", {
        method: "POST",
        json: { name: form.name.value, path: remote ? "" : value, url: remote ? value : "", format: form.format.value },
      });
      form.reset();
      const message = result.feed.status === "ok" ? "" : "The feed was added, but it did not load: " + result.feed.last_error;
      await renderFeeds(list, note, message);
    } catch (err) {
      error.textContent = err.message;
    }
    button.disabled = false;
    button.textContent = "Add feed";
  });
  return form;
}

async function renderFeeds(list, note, message) {
  clear(list);
  if (message) list.append(el("p", { className: "status error" }, message));
  const status = el("p", { className: "status" }, "Loading feeds…");
  list.append(status);
  try {
    const [data, current] = await Promise.all([api("/api/v1/feeds"), api("/api/v1/settings")]);
    status.remove();
    note.textContent = current.feeds_source === "console"
      ? "This list is managed here; feeds in config.json are no longer applied. A failed sync keeps the names from the last successful load."
      : "These feeds come from config.json. Adding or removing one here moves the list to this console for good. A failed sync keeps the names from the last successful load.";
    if (!data.feeds.length) {
      list.append(el("p", { className: "status" }, "No feeds yet. Only manual rules are blocking names."));
      return;
    }
    list.append(table(["Name", "Source", "Format", "Status", "Names", "Rejected", "Last sync", ""], data.feeds.map((feed) => {
      const cells = [
        feed.name,
        el("span", { className: "path" }, feed.source),
        feed.format,
        tag(feed.status === "ok" ? "ok" : feed.status === "pending" ? "pending" : "error", feedStatus(feed.status)),
        number(feed.domains_count),
        number(feed.rejected_count),
        feed.last_error ? formatTime(feed.last_sync_at) + " — " + feed.last_error : formatTime(feed.last_sync_at),
      ];
      if (me.role === "admin") {
        const actions = el("span", { className: "actions" });
        const sync = el("button", { type: "button", className: "secondary" }, "Sync now");
        sync.addEventListener("click", async () => {
          sync.disabled = true;
          sync.textContent = "Syncing…";
          try {
            await api("/api/v1/feeds/" + feed.id + "/sync", { method: "POST" });
            await renderFeeds(list, note, "");
          } catch (err) {
            await renderFeeds(list, note, err.message);
          }
        });
        const remove = dangerButton("Remove", "Remove the feed " + feed.name + "? Its names stop being blocked right away.", async () => {
          try {
            await api("/api/v1/feeds/" + feed.id, { method: "DELETE" });
            await renderFeeds(list, note, "");
          } catch (err) {
            await renderFeeds(list, note, err.message);
          }
        });
        actions.append(sync, remove);
        cells.push(actions);
      } else {
        cells.push("—");
      }
      return cells;
    })));
  } catch (err) {
    showError(status, err);
  }
}

/* Settings */

const settingFields = {
  blocked_rcode: "Blocked answer",
  upstream: "Upstream resolver",
  upstream_timeout_seconds: "Upstream timeout",
  retention_days: "Log retention",
  feed_sync_interval_hours: "Feed sync interval",
  log_mode: "Logging",
};

async function loadSettings() {
  const root = start("Settings");
  root.append(el("p", { className: "lede" }, "Changes apply to the next query, with no restart. Listen addresses and the database path stay in config.json because they need one."));
  const status = el("p", { className: "status" }, "Loading settings…");
  root.append(status);
  try {
    const current = await api("/api/v1/settings");
    status.remove();
    root.append(settingsForm(current));
  } catch (err) {
    showError(status, err);
  }
}

function settingsForm(current) {
  const admin = me.role === "admin";
  const form = el("form", { className: "settings" });
  const answers = el("section", { className: "panel" });
  answers.append(el("h2", null, "DNS answers"));
  answers.append(settingRow(current, "blocked_rcode", select("blocked_rcode", [
    ["REFUSED", "REFUSED — the resolver declines to answer"],
    ["NXDOMAIN", "NXDOMAIN — the name does not exist"],
    ["SERVFAIL", "SERVFAIL — the resolver failed"],
  ]), "What a client gets back for a blocked name."));
  answers.append(settingRow(current, "upstream", input("upstream", { placeholder: "1.1.1.1:53" }), "Where allowed queries are forwarded, as host:port."));
  answers.append(settingRow(current, "upstream_timeout_seconds", input("upstream_timeout_seconds", { type: "number", min: "1", max: "30" }, "seconds"), "How long to wait before answering SERVFAIL. 1 to 30."));
  form.append(answers);

  const upkeep = el("section", { className: "panel" });
  upkeep.append(el("h2", null, "Housekeeping"));
  upkeep.append(settingRow(current, "retention_days", input("retention_days", { type: "number", min: "1", max: "3650" }, "days"), "Older log rows and daily counts are deleted. The overview covers this window."));
  upkeep.append(settingRow(current, "feed_sync_interval_hours", input("feed_sync_interval_hours", { type: "number", min: "1", max: "720" }, "hours"), "How often every feed is downloaded again."));
  form.append(upkeep);

  Object.keys(settingFields).forEach((key) => {
    if (form.elements[key]) form.elements[key].value = String(current.values[key]);
  });
  const foot = el("div", { className: "form-foot" });
  const message = el("p", { className: "saved", role: "status" }, "");
  if (admin) {
    const button = el("button", { type: "submit" }, "Save changes");
    foot.append(button, message);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      button.disabled = true;
      message.className = "saved";
      message.textContent = "Saving…";
      form.querySelectorAll(".invalid").forEach((node) => node.classList.remove("invalid"));
      try {
        const next = await api("/api/v1/settings", {
          method: "PUT",
          json: {
            blocked_rcode: form.blocked_rcode.value,
            upstream: form.upstream.value,
            upstream_timeout_seconds: Number(form.upstream_timeout_seconds.value),
            retention_days: Number(form.retention_days.value),
            feed_sync_interval_hours: Number(form.feed_sync_interval_hours.value),
          },
        });
        const fresh = settingsForm(next);
        form.replaceWith(fresh);
        const changed = JSON.stringify(next.values) !== JSON.stringify(current.values);
        fresh.querySelector(".saved").textContent = changed ? "Saved. This applies to the next query." : "Nothing changed.";
      } catch (err) {
        button.disabled = false;
        message.className = "saved error";
        message.textContent = err.message;
        if (err.field && form.elements[err.field]) {
          form.elements[err.field].classList.add("invalid");
          form.elements[err.field].focus();
        }
      }
    });
  } else {
    form.querySelectorAll("input, select").forEach((node) => { node.disabled = true; });
    foot.append(el("p", { className: "note" }, "Only an administrator can change these settings."));
  }
  form.append(foot);
  form.append(el("p", { className: "note" }, "What gets logged is chosen on the Logs page. Currently: " + logModeName(current.values.log_mode) + "."));
  return form;
}

function settingRow(current, key, control, help) {
  const row = el("div", { className: "setting" });
  const text = el("div");
  text.append(el("label", { for: key }, settingFields[key]), el("p", { className: "hint" }, help));
  const side = el("div");
  side.append(control, el("p", { className: "source" }, sourceText(current, key)));
  row.append(text, side);
  return row;
}

function sourceText(current, key) {
  const saved = current.saved[key];
  if (!saved) return "From config.json";
  let text = "Set by " + saved.updated_by + " on " + formatTime(saved.updated_at);
  if (String(current.file[key]) !== String(current.values[key])) text += " · config.json has " + current.file[key];
  return text;
}

/* Users */

async function loadUsers() {
  const root = start("Users");
  if (me.role !== "admin") {
    root.append(el("p", { className: "status" }, "Only an administrator can manage accounts."));
    return;
  }
  root.append(el("p", { className: "note" }, "Administrators can change rules, feeds, settings, and accounts. Analysts can look but not change. New accounts and reset passwords are temporary: the person picks their own at first sign-in."));
  const list = el("div");
  const form = el("form", { className: "inline-form panel" });
  form.append(el("h2", null, "Add an account"));
  form.append(field("Username", "username", { autocomplete: "off", required: "" }));
  form.append(field("Temporary password", "password", { type: "password", autocomplete: "new-password", minlength: "8", required: "" }));
  form.append(selectField("Role", "role", [["analyst", "Analyst"], ["admin", "Administrator"]]));
  const button = el("button", { type: "submit" }, "Add account");
  form.append(button);
  const error = el("p", { className: "form-error" }, "");
  form.append(error);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.textContent = "";
    button.disabled = true;
    try {
      await api("/api/v1/users", { method: "POST", json: { username: form.username.value, password: form.password.value, role: form.role.value } });
      form.reset();
      await renderUsers(list, "");
    } catch (err) {
      error.textContent = err.message;
    }
    button.disabled = false;
  });
  root.append(form, list);
  await renderUsers(list, "");
}

async function renderUsers(list, message) {
  clear(list);
  const notice = el("p", { className: "form-error" }, message);
  list.append(notice);
  const resetSlot = el("div");
  list.append(resetSlot);
  const status = el("p", { className: "status" }, "Loading accounts…");
  list.append(status);
  try {
    const data = await api("/api/v1/users");
    status.remove();
    list.append(table(["Username", "Role", "Password", "Created", ""], data.users.map((user) => {
      const state = user.must_change_password ? tag("pending", "Temporary") : tag("ok", "Set");
      if (user.username === me.username) {
        return [user.username, roleName(user.role), state, formatTime(user.created_at), el("a", { href: "/account", className: "you" }, "Your account")];
      }
      const actions = el("span", { className: "actions" });
      const reset = el("button", { type: "button", className: "secondary" }, "Reset password");
      reset.addEventListener("click", () => showReset(resetSlot, list, user));
      const remove = dangerButton("Delete", "Delete the account " + user.username + "? They are signed out at once.", async () => {
        try {
          await api("/api/v1/users/" + user.id, { method: "DELETE" });
          await renderUsers(list, "");
        } catch (err) {
          notice.textContent = err.message;
        }
      });
      actions.append(reset, remove);
      return [user.username, roleName(user.role), state, formatTime(user.created_at), actions];
    })));
  } catch (err) {
    showError(status, err);
  }
}

function showReset(slot, list, user) {
  clear(slot);
  const form = el("form", { className: "inline-form panel reset" });
  const inputId = "reset-" + user.id;
  const wrap = el("div", { className: "wide" });
  wrap.append(
    el("label", { for: inputId }, "Temporary password for " + user.username),
    el("input", { id: inputId, name: "password", type: "password", autocomplete: "new-password", minlength: "8", required: "" }),
  );
  form.append(wrap);
  const save = el("button", { type: "submit" }, "Set password");
  const cancel = el("button", { type: "button", className: "secondary" }, "Cancel");
  cancel.addEventListener("click", () => clear(slot));
  form.append(save, cancel);
  const error = el("p", { className: "form-error" }, "");
  form.append(error);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    save.disabled = true;
    try {
      await api("/api/v1/users/" + user.id + "/password", { method: "POST", json: { password: form.password.value } });
      await renderUsers(list, "");
      const done = list.querySelector(".form-error");
      done.className = "saved";
      done.textContent = user.username + " was signed out and must choose a new password at next sign-in.";
    } catch (err) {
      error.textContent = err.message;
      save.disabled = false;
    }
  });
  slot.append(form);
  form.password.focus();
}

/* Account */

function loadAccount() {
  const root = start("Account");
  root.append(el("p", { className: "lede" }, "Signed in as " + me.username + ", " + roleName(me.role).toLowerCase() + "."));
  if (me.must_change_password) {
    const notice = el("section", { className: "notice" });
    notice.append(
      el("strong", null, "Choose a new password to continue"),
      el("span", null, "This account is using a temporary password. The rest of the console opens once you set your own."),
    );
    root.append(notice);
  }
  const form = el("form", { className: "panel password-form" });
  form.append(el("h2", null, "Change password"));
  form.append(field("Current password", "current", { type: "password", autocomplete: "current-password", required: "" }));
  form.append(field("New password", "next", { type: "password", autocomplete: "new-password", minlength: "8", required: "" }));
  form.append(field("New password again", "again", { type: "password", autocomplete: "new-password", minlength: "8", required: "" }));
  form.append(el("p", { className: "hint" }, "At least 8 characters. Your other sessions are signed out."));
  const button = el("button", { type: "submit" }, "Change password");
  const message = el("p", { className: "saved", role: "status" }, "");
  form.append(button, message);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    message.className = "saved error";
    if (form.next.value !== form.again.value) {
      message.textContent = "The two new passwords do not match.";
      form.again.focus();
      return;
    }
    button.disabled = true;
    message.className = "saved";
    message.textContent = "Saving…";
    try {
      await api("/api/v1/account/password", { method: "POST", json: { current_password: form.current.value, new_password: form.next.value } });
      if (me.must_change_password) {
        window.location.assign("/dashboard");
        return;
      }
      form.reset();
      message.textContent = "Password changed. Your other sessions were signed out.";
    } catch (err) {
      message.className = "saved error";
      message.textContent = err.message;
    }
    button.disabled = false;
  });
  root.append(form);
}

/* Audit */

async function loadAudit() {
  const root = start("Audit");
  root.append(el("p", { className: "note" }, "Sign-ins, accounts, settings, rules, and feeds. Passwords and session tokens are never recorded."));
  const status = el("p", { className: "status" }, "Loading the audit log…");
  root.append(status);
  try {
    const data = await api("/api/v1/audit?limit=50&offset=0");
    status.remove();
    if (!data.audit.length) {
      root.append(el("p", { className: "status" }, "No administrative actions yet."));
      return;
    }
    const actions = {
      login_success: "Signed in",
      login_failure: "Sign-in failed",
      logout: "Signed out",
      password_change: "Changed their password",
      password_reset: "Reset a password",
      user_create: "Added an account",
      user_delete: "Deleted an account",
      settings_update: "Changed settings",
      rule_create: "Added a rule",
      rule_delete: "Deleted a rule",
      feed_create: "Added a feed",
      feed_delete: "Removed a feed",
      feed_sync: "Synced a feed",
    };
    root.append(table(["Time", "User", "Action", "Object", "Result"], data.audit.map((row) => [
      formatTime(row.timestamp),
      row.username,
      actions[row.action] || row.action,
      auditObject(row),
      auditResult(row.result),
    ])));
  } catch (err) {
    showError(status, err);
  }
}

function auditObject(row) {
  if (row.object_type === "session") return "—";
  if (row.object_type === "settings") {
    return row.object_id.split(",").map((key) => settingFields[key] || key).join(", ");
  }
  return [row.object_type, row.object_id].filter(Boolean).join(" ");
}

function auditResult(result) {
  if (result === "success") return tag("ok", "Success");
  if (result === "rate_limited") return tag("blocked", "Paused after repeated failures");
  return tag("blocked", "Failed");
}

/* Building blocks */

function start(title) {
  const root = document.querySelector("#content");
  clear(root);
  root.append(el("h1", null, title));
  return root;
}

function eventTable(events, empty) {
  if (!events || !events.length) return el("p", { className: "status" }, empty);
  return table(["Time", "Client", "Name", "Type", "Via", "Decision", "Answer", "Match"], events.map((event) => [
    formatTime(event.timestamp),
    mono(event.client_ip),
    mono(event.qname),
    event.qtype,
    event.transport.toUpperCase(),
    tag(event.action.toLowerCase(), label(event.action)),
    event.rcode,
    matchText(event),
  ]));
}

function matchText(event) {
  if (!event.matched_source) return "—";
  const source = event.matched_source === "manual" ? "Manual rule" : event.matched_source;
  return event.matched_domain ? source + " · " + event.matched_domain : source;
}

function cards(items) {
  const wrap = el("section", { className: "cards" });
  items.forEach(([name, value, kind]) => {
    const card = el("article", { className: kind ? "card " + kind : "card" });
    card.append(el("span", null, name), el("strong", null, value));
    wrap.append(card);
  });
  return wrap;
}

function countPanel(title, column, rows, key, empty) {
  const panel = el("section", { className: "panel" });
  panel.append(panelHead(title));
  if (!rows || !rows.length) {
    panel.append(el("p", { className: "status" }, empty));
    return panel;
  }
  panel.append(table([column, "Blocks"], rows.map((row) => [mono(row[key]), number(row.count)])));
  return panel;
}

function panelHead(title, extra) {
  const head = el("div", { className: "panel-head" });
  head.append(el("h2", null, title));
  if (extra) head.append(extra);
  return head;
}

function mono(text) {
  return el("span", { className: "mono" }, text == null || text === "" ? "—" : String(text));
}

function table(headers, rows) {
  const wrap = el("div", { className: "table-wrap" });
  const tableNode = el("table");
  const head = el("thead");
  const headRow = el("tr");
  headers.forEach((header) => headRow.append(el("th", { scope: "col" }, header)));
  head.append(headRow);
  const body = el("tbody");
  rows.forEach((cells) => {
    const row = el("tr");
    cells.forEach((cell) => {
      const td = el("td");
      if (cell instanceof Node) td.append(cell);
      else td.textContent = cell == null || cell === "" ? "—" : String(cell);
      if (td.textContent === "—") td.className = "none";
      if (cell instanceof Node && cell.matches("button, .actions, .you")) td.className = "end";
      row.append(td);
    });
    body.append(row);
  });
  tableNode.append(head, body);
  wrap.append(tableNode);
  return wrap;
}

function field(labelText, name, attrs) {
  const wrap = el("div");
  wrap.append(el("label", { for: name }, labelText), el("input", Object.assign({ id: name, name: name, type: "text" }, attrs)));
  return wrap;
}

function input(name, attrs, unit) {
  const control = el("input", Object.assign({ id: name, name: name, type: "text" }, attrs));
  if (!unit) return control;
  const wrap = el("span", { className: "with-unit" });
  wrap.append(control, el("span", null, unit));
  return wrap;
}

function select(name, options) {
  const node = el("select", { id: name, name: name });
  options.forEach(([value, text]) => node.append(el("option", { value: value }, text)));
  return node;
}

function selectField(labelText, name, options) {
  const wrap = el("div");
  wrap.append(el("label", { for: name }, labelText), select(name, options));
  return wrap;
}

function dangerButton(text, question, action) {
  const button = el("button", { type: "button", className: "danger" }, text);
  button.addEventListener("click", () => {
    if (window.confirm(question)) action();
  });
  return button;
}

function showError(status, err) {
  status.className = "status error";
  status.textContent = err.message;
}

function tag(kind, text) {
  return el("span", { className: "tag " + kind }, text);
}

function label(value) {
  const names = {
    ALLOWED: "Allowed", BLOCKED: "Blocked", ERROR: "Error",
    allow: "Allow", deny: "Deny",
    exact: "Exact name", suffix: "Name and subdomains",
  };
  return names[value] || value;
}

function roleName(role) {
  return role === "admin" ? "Administrator" : "Analyst";
}

function logModeName(mode) {
  const found = logModes.find(([value]) => value === mode);
  return found ? found[1].toLowerCase() : mode;
}

function plural(count, word) {
  return count + " " + word + (count === 1 ? "" : "s");
}

function number(value) {
  return new Intl.NumberFormat().format(Number(value || 0));
}

function feedStatus(status) {
  const names = { ok: "OK", pending: "Pending", error: "Error" };
  return names[status] || status;
}

function percent(value) {
  const number = Number(value || 0);
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(number) + "%";
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function el(tagName, attrs, text) {
  const node = document.createElement(tagName);
  if (attrs) {
    Object.entries(attrs).forEach(([key, value]) => {
      if (value == null) return;
      if (key === "className") node.className = value;
      else node.setAttribute(key, value);
    });
  }
  if (text != null) node.textContent = text;
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

async function api(path, options) {
  const request = options || {};
  const method = request.method || "GET";
  const headers = { Accept: "application/json" };
  let body;
  if (request.json != null) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(request.json);
  }
  if (csrf && method !== "GET" && method !== "HEAD") {
    headers["X-CSRF-Token"] = csrf;
  }
  const response = await fetch(path, { method: method, headers: headers, body: body, credentials: "same-origin" });
  if (response.status === 204) return null;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (data.must_change_password && page !== "account") {
      window.location.assign("/account");
    }
    const error = new Error(data.error || "The request failed.");
    error.status = response.status;
    error.field = data.field;
    throw error;
  }
  return data;
}
