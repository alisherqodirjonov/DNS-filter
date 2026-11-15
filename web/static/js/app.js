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
  document.querySelector("#who").textContent = me.username + " · " + me.role;
  document.querySelector("#sign-out").addEventListener("click", signOut);
  if (me.role === "admin") {
    document.querySelectorAll("[data-admin]").forEach((node) => {
      node.hidden = false;
    });
  }
  const screens = {
    dashboard: loadDashboard,
    events: loadEvents,
    rules: loadRules,
    feeds: loadFeeds,
    audit: loadAudit,
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
    await api("/api/v1/auth/login", {
      method: "POST",
      json: {
        username: form.username.value,
        password: form.password.value,
      },
    });
    window.location.assign("/dashboard");
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

async function loadDashboard() {
  const root = document.querySelector("#content");
  clear(root);
  root.append(el("h1", null, "Overview"));
  root.append(el("p", { className: "lede" }, "Counts come from the queries still kept in the local log."));
  const status = el("p", { className: "status" }, "Loading the summary…");
  root.append(status);
  try {
    const data = await api("/api/v1/dashboard/summary");
    status.remove();
    root.append(cards([
      ["Queries", String(data.total)],
      ["Allowed", String(data.allowed)],
      ["Blocked", String(data.blocked)],
      ["Block ratio", percent(data.block_ratio)],
      ["Feed names", String(data.feed_domains)],
    ]));
    const split = el("div", { className: "split" });
    split.append(countPanel("Most blocked names", data.top_blocked_domains, "qname", "Nothing has been blocked yet."));
    split.append(countPanel("Clients with the most blocks", data.top_blocked_clients, "client_ip", "No client has been blocked yet."));
    root.append(split);
    root.append(el("h2", null, "Recent queries"));
    root.append(eventTable(data.recent_events, "No queries yet. Point a test client at this resolver and they will show up here."));
  } catch (err) {
    status.className = "status error";
    status.textContent = err.message;
  }
}

function loadEvents() {
  const root = document.querySelector("#content");
  clear(root);
  root.append(el("h1", null, "DNS events"));
  root.append(el("p", { className: "lede" }, "Each row is one query this filter handled. Blocked names were not sent upstream."));
  const form = el("form", { className: "filters" });
  form.append(field("Domain contains", "qname", "text", "example.test"));
  form.append(selectField("Action", "decision", [["", "Any action"], ["ALLOWED", "Allowed"], ["BLOCKED", "Blocked"], ["ERROR", "Error"]]));
  const button = el("button", { type: "submit" }, "Apply");
  form.append(button);
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
  render();

  async function render() {
    clear(list);
    const status = el("p", { className: "status" }, "Loading events…");
    list.append(status);
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    const qname = form.qname.value.trim();
    const selected = form.decision.value;
    if (qname) params.set("qname", qname);
    if (selected) params.set("action", selected);
    try {
      const data = await api("/api/v1/events?" + params.toString());
      status.remove();
      list.append(eventTable(data.events, "No events match this filter."));
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
      status.className = "status error";
      status.textContent = err.message;
    }
  }
}

async function loadRules() {
  const root = document.querySelector("#content");
  clear(root);
  root.append(el("h1", null, "Rules"));
  root.append(el("p", { className: "note" }, "A suffix rule also covers subdomains. An allow rule forwards the name even when a deny rule or a feed would block it."));
  if (me.role === "admin") {
    const form = el("form", { className: "rule-form panel" });
    form.append(field("Domain", "domain", "text", "example.test"));
    form.append(selectField("Type", "rule_type", [["deny", "Deny"], ["allow", "Allow"]]));
    form.append(selectField("Match", "match_type", [["exact", "Exact name"], ["suffix", "Name and subdomains"]]));
    form.append(field("Description", "description", "text", "Optional note"));
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
      const cells = [rule.domain, label(rule.rule_type), rule.match_type, rule.description || "—", rule.created_by];
      if (me.role === "admin") {
        const remove = el("button", { type: "button", className: "danger" }, "Delete");
        remove.addEventListener("click", async () => {
          if (!window.confirm("Delete the rule for " + rule.domain + "?")) return;
          try {
            await api("/api/v1/rules/" + rule.id, { method: "DELETE" });
            await loadRules();
          } catch (err) {
            notice.textContent = err.message;
          }
        });
        cells.push(remove);
      } else {
        cells.push("—");
      }
      return cells;
    })));
  } catch (err) {
    status.className = "status error";
    status.textContent = err.message;
  }
}

async function loadFeeds() {
  const root = document.querySelector("#content");
  clear(root);
  root.append(el("h1", null, "Threat feeds"));
  root.append(el("p", { className: "note" }, "Feeds are listed in the configuration file. A failed sync keeps the names from the last successful load."));
  const list = el("div");
  root.append(list);
  await renderFeeds(list, "");
}

async function renderFeeds(list, message) {
  clear(list);
  if (message) list.append(el("p", { className: "status error" }, message));
  const status = el("p", { className: "status" }, "Loading feeds…");
  list.append(status);
  try {
    const data = await api("/api/v1/feeds");
    status.remove();
    if (!data.feeds.length) {
      list.append(el("p", { className: "status" }, "No feeds are configured."));
      return;
    }
    list.append(table(["Name", "Source", "Format", "Status", "Names", "Rejected", "Last sync", ""], data.feeds.map((feed) => {
      const cells = [
        feed.name,
        feed.source,
        feed.format,
        tag(feed.status === "ok" ? "ok" : feed.status === "pending" ? "pending" : "error", feed.status),
        String(feed.domains_count),
        String(feed.rejected_count),
        feed.last_error ? formatTime(feed.last_sync_at) + " — " + feed.last_error : formatTime(feed.last_sync_at),
      ];
      if (me.role === "admin") {
        const button = el("button", { type: "button", className: "secondary" }, "Sync now");
        button.addEventListener("click", async () => {
          button.disabled = true;
          button.textContent = "Syncing…";
          try {
            await api("/api/v1/feeds/" + feed.id + "/sync", { method: "POST" });
            await renderFeeds(list, "");
          } catch (err) {
            await renderFeeds(list, err.message);
          }
        });
        cells.push(button);
      } else {
        cells.push("—");
      }
      return cells;
    })));
  } catch (err) {
    status.className = "status error";
    status.textContent = err.message;
  }
}

async function loadAudit() {
  const root = document.querySelector("#content");
  clear(root);
  root.append(el("h1", null, "Audit"));
  root.append(el("p", { className: "note" }, "Sign-ins, rule changes, and feed syncs. Passwords and session tokens are not recorded."));
  const status = el("p", { className: "status" }, "Loading the audit log…");
  root.append(status);
  try {
    const data = await api("/api/v1/audit?limit=50&offset=0");
    status.remove();
    if (!data.audit.length) {
      root.append(el("p", { className: "status" }, "No administrative actions yet."));
      return;
    }
    root.append(table(["Time", "User", "Action", "Object", "Result"], data.audit.map((row) => [
      formatTime(row.timestamp),
      row.username,
      row.action,
      [row.object_type, row.object_id].filter(Boolean).join(" "),
      row.result,
    ])));
  } catch (err) {
    status.className = "status error";
    status.textContent = err.message;
  }
}

function eventTable(events, empty) {
  if (!events || !events.length) return el("p", { className: "status" }, empty);
  return table(["Time", "Client", "Name", "Type", "Via", "Action", "Response", "Match"], events.map((event) => [
    formatTime(event.timestamp),
    event.client_ip,
    event.qname,
    event.qtype,
    event.transport,
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
  items.forEach(([name, value]) => {
    const card = el("article", { className: "card" });
    card.append(el("span", null, name), el("strong", null, value));
    wrap.append(card);
  });
  return wrap;
}

function countPanel(title, rows, key, empty) {
  const panel = el("section", { className: "panel" });
  panel.append(el("h2", null, title));
  if (!rows || !rows.length) {
    panel.append(el("p", { className: "status" }, empty));
    return panel;
  }
  panel.append(table(["Name", "Count"], rows.map((row) => [row[key], String(row.count)])));
  return panel;
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
      row.append(td);
    });
    body.append(row);
  });
  tableNode.append(head, body);
  wrap.append(tableNode);
  return wrap;
}

function field(labelText, name, type, placeholder) {
  const wrap = el("div");
  const input = el("input", { id: name, name: name, type: type, placeholder: placeholder });
  wrap.append(el("label", { for: name }, labelText), input);
  return wrap;
}

function selectField(labelText, name, options) {
  const wrap = el("div");
  const select = el("select", { id: name, name: name });
  options.forEach(([value, text]) => select.append(el("option", { value: value }, text)));
  wrap.append(el("label", { for: name }, labelText), select);
  return wrap;
}

function tag(kind, text) {
  return el("span", { className: "tag " + kind }, text);
}

function label(value) {
  const names = { ALLOWED: "Allowed", BLOCKED: "Blocked", ERROR: "Error", allow: "Allow", deny: "Deny" };
  return names[value] || value;
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
  const settings = options || {};
  const method = settings.method || "GET";
  const headers = { Accept: "application/json" };
  let body;
  if (settings.json != null) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(settings.json);
  }
  if (csrf && method !== "GET" && method !== "HEAD") {
    headers["X-CSRF-Token"] = csrf;
  }
  const response = await fetch(path, { method: method, headers: headers, body: body, credentials: "same-origin" });
  if (response.status === 204) return null;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data.error || "The request failed.");
    error.status = response.status;
    throw error;
  }
  return data;
}
