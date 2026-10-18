"use strict";
// All dynamic content is inserted with textContent / DOM APIs, never innerHTML.

const $ = (sel, root = document) => root.querySelector(sel);
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, "");
    else if (v !== false && v != null) el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
}

let state = null;
let es = null;

async function api(path, opts = {}) {
  const o = { method: opts.method || "GET", headers: { "X-Warrant": "1" }, credentials: "same-origin" };
  if (opts.body !== undefined) { o.headers["Content-Type"] = "application/json"; o.body = JSON.stringify(opts.body); }
  const r = await fetch("/api" + path, o);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(data.error || r.statusText); e.data = data; e.status = r.status; throw e; }
  return data;
}

const VIEWS = { dashboard: "Dashboard", engagement: "Engagement", run: "Run tool", jobs: "Jobs", findings: "Findings", reports: "Reports", audit: "Audit" };

async function refresh() {
  state = await api("/state");
  const e = state.engagement;
  const badge = $("#eng-badge");
  badge.textContent = e ? `${e.name}${e.client ? " · " + e.client : ""}` : "no engagement";
  badge.className = "badge" + (e ? "" : " muted");
  const nav = $("#nav");
  nav.replaceChildren(...Object.entries(VIEWS).map(([k, label]) => h("a", { href: "#" + k, class: location.hash.slice(1) === k ? "active" : "" }, label)));
}

function sevBadge(s) { return h("span", { class: "sev " + s }, s); }
function errBox(e) { return h("p", { class: "bad" }, e.message || String(e)); }

// ---------- views ----------
const views = {
  async dashboard(root) {
    const e = state.engagement;
    root.append(h("h2", {}, "Dashboard"));
    if (!e) { root.append(h("p", { class: "muted" }, "No active engagement. Create or activate one under Engagement.")); }
    else {
      root.append(h("div", { class: "grid" }, state.severities.map(s => h("div", { class: "tile" }, h("b", {}, e.counts[s]), sevBadge(s)))));
      root.append(h("div", { class: "card" }, h("b", {}, "Scope: "), (e.includes.join(", ") || "none defined: all runs are blocked"), h("br"),
        h("span", { class: "muted" }, "Excluded: " + (e.excludes.join(", ") || "none"))));
    }
    const avail = state.tools.filter(t => t.available).length;
    root.append(h("div", { class: "card" }, `${avail} of ${state.tools.length} tools available. `, h("a", { href: "#run" }, "Run one")));
  },

  async engagement(root) {
    root.append(h("h2", {}, "Engagement"));
    const e = state.engagement;
    if (e) {
      const list = (items, exclude) => h("div", {}, items.map(i => h("span", { class: "tag" }, i,
        h("button", { title: "remove", onclick: async () => { await api("/scope?item=" + encodeURIComponent(i), { method: "DELETE" }); go(); } }, "×"))));
      const item = h("input", { placeholder: "10.0.0.0/24, 10.0.0.5, 10.0.0.1-50, example.com" });
      const ex = h("input", { type: "checkbox", style: "width:auto" });
      const msg = h("p");
      root.append(h("div", { class: "card" }, h("h3", {}, "Scope"), h("label", {}, "In scope"), list(e.includes), h("label", {}, "Excluded"), list(e.excludes),
        h("div", { class: "row", style: "margin-top:1rem" }, h("div", {}, h("label", {}, "Add entry"), item),
          h("label", { style: "flex:0 0 auto" }, ex, " exclude"),
          h("button", { class: "primary", onclick: async () => { try { await api("/scope", { method: "POST", body: { item: item.value, exclude: ex.checked } }); go(); } catch (x) { msg.replaceChildren(errBox(x)); } } }, "Add")), msg));
      const t = h("input", { placeholder: "target to test against scope" }); const res = h("p");
      root.append(h("div", { class: "card" }, h("h3", {}, "Scope checker"), h("div", { class: "row" }, t,
        h("button", { onclick: async () => { try { const d = await api("/scope/check?target=" + encodeURIComponent(t.value));
          res.replaceChildren(h("span", { class: d.allowed ? "ok" : "bad" }, d.allowed ? "IN SCOPE" : "OUT OF SCOPE"), " — " + d.reason + (d.resolved.length ? " (" + d.resolved.join(", ") + ")" : ""), ...d.warnings.map(w => h("div", { class: "warn" }, "! " + w))); } catch (x) { res.replaceChildren(errBox(x)); } } }, "Check")), res));
    }
    const f = {}; const fields = [["name", "Name (letters, digits, - _ .)"], ["client", "Client"], ["tester", "Tester"], ["scope", "In scope (comma separated)"], ["exclude", "Excluded (comma separated)"]];
    const msg = h("p");
    root.append(h("div", { class: "card" }, h("h3", {}, "New engagement"),
      ...fields.map(([k, label]) => [h("label", {}, label), f[k] = h("input")]),
      h("button", { class: "primary", style: "margin-top:1rem", onclick: async () => {
        const split = s => s.split(",").map(x => x.trim()).filter(Boolean);
        try { await api("/engagements", { method: "POST", body: { name: f.name.value, client: f.client.value, tester: f.tester.value, scope: split(f.scope.value), exclude: split(f.exclude.value) } }); go(); }
        catch (x) { msg.replaceChildren(errBox(x)); } } }, "Create and activate"), msg));
    if (state.engagements.length) {
      root.append(h("div", { class: "card" }, h("h3", {}, "Switch engagement"), ...state.engagements.map(n =>
        h("button", { style: "margin:0 .4rem .4rem 0", onclick: async () => { await api(`/engagements/${encodeURIComponent(n)}/activate`, { method: "POST" }); go(); } }, n))));
    }
  },

  async run(root) {
    root.append(h("h2", {}, "Run tool"));
    if (!state.engagement) { root.append(h("p", { class: "muted" }, "Activate an engagement first.")); return; }
    const list = h("div", { class: "toollist" }); const pane = h("div");
    root.append(h("div", { class: "split" }, list, pane));
    let cat = null;
    for (const t of [...state.tools].sort((a, b) => (a.category + a.id).localeCompare(b.category + b.id))) {
      if (t.category !== cat) { cat = t.category; list.append(h("h4", {}, cat)); }
      list.append(h("a", { onclick: ev => { list.querySelectorAll("a").forEach(a => a.classList.remove("sel")); ev.currentTarget.classList.add("sel"); form(t); } },
        h("span", { class: t.available ? "ok" : "bad" }, t.available ? "● " : "○ "), t.label));
    }
    function form(t) {
      const inputs = {}; const out = h("pre", { class: "out", hidden: true }); const msg = h("div");
      const box = h("div", { class: "card" }, h("h3", { style: "margin-top:0" }, t.label), h("p", { class: "muted" }, t.description),
        !t.available && h("p", { class: "warn" }, "Not installed. " + t.install),
        ...t.params.map(p => {
          let el;
          if (p.kind === "choice") el = h("select", {}, (p.required ? [] : [h("option", { value: "" }, "(default)")]), p.choices.map(c => h("option", { value: c, selected: c === p.default }, c)));
          else if (p.kind === "bool") el = h("input", { type: "checkbox", style: "width:auto", checked: !!p.default });
          else el = h("input", { type: p.kind === "int" ? "number" : "text", value: p.default ?? "", min: p.min, max: p.max, placeholder: p.kind === "flags" ? "allow-listed flags only" : "" });
          inputs[p.name] = [p, el];
          return [h("label", {}, p.label + (p.required && p.default == null ? " *" : "")), el];
        }),
        h("div", { style: "margin-top:1rem" }, h("button", { class: "primary", onclick: run }, "Run")), msg, out);
      pane.replaceChildren(box);
      async function run() {
        const params = {};
        for (const [name, [p, el]] of Object.entries(inputs)) {
          if (p.kind === "bool") params[name] = el.checked; else if (el.value !== "") params[name] = el.value;
        }
        msg.replaceChildren(); out.hidden = false; out.textContent = "";
        try {
          const job = await api("/run", { method: "POST", body: { tool: t.id, params } });
          stream(job.id, out, msg);
        } catch (x) {
          const lines = x.data && x.data.decisions ? x.data.decisions.map(d => `${d.target}: ${d.reason}`) : [];
          msg.replaceChildren(errBox(x), ...lines.map(l => h("div", { class: "bad" }, l))); out.hidden = true;
        }
      }
    }
  },

  async jobs(root) {
    root.append(h("h2", {}, "Jobs"));
    const jobs = await api("/jobs"); const out = h("pre", { class: "out", hidden: true });
    root.append(h("table", {}, h("tr", {}, ["Tool", "Status", "Started", "Findings", ""].map(x => h("th", {}, x))),
      ...jobs.map(j => h("tr", {}, h("td", {}, j.tool), h("td", {}, j.status), h("td", {}, j.started), h("td", {}, (j.summary.findings || []).length),
        h("td", {}, h("button", { onclick: async () => { const d = await api("/jobs/" + j.id); out.hidden = false; out.textContent = d.output.join("\n"); } }, "Output"),
          j.status === "running" && h("button", { class: "danger", onclick: async () => { await api(`/jobs/${j.id}/cancel`, { method: "POST" }); go(); } }, "Cancel"))))), out);
    if (!jobs.length) root.append(h("p", { class: "muted" }, "No jobs yet."));
  },

  async findings(root) {
    root.append(h("h2", {}, "Findings"));
    if (!state.engagement) { root.append(h("p", { class: "muted" }, "Activate an engagement first.")); return; }
    const fs = await api("/findings");
    root.append(h("table", {}, h("tr", {}, ["ID", "Severity", "Title", "Affected", "Status", ""].map(x => h("th", {}, x))), ...fs.map(f => h("tr", {},
      h("td", {}, f.id), h("td", {}, sevBadge(f.severity)), h("td", {}, h("b", {}, f.title), h("div", { class: "muted" }, f.description.slice(0, 240))), h("td", {}, f.affected),
      h("td", {}, h("select", { onchange: async ev => { await api("/findings/" + f.id, { method: "PATCH", body: { status: ev.target.value } }); } },
        state.statuses.map(s => h("option", { value: s, selected: s === f.status }, s.replace("_", " "))))),
      h("td", {}, h("button", { class: "danger", onclick: async () => { if (confirm("Delete " + f.id + "?")) { await api("/findings/" + f.id, { method: "DELETE" }); go(); } } }, "×"))))));
    if (!fs.length) root.append(h("p", { class: "muted" }, "No findings yet."));
    const f = {}; const msg = h("p");
    root.append(h("div", { class: "card" }, h("h3", {}, "Add finding"),
      h("label", {}, "Title"), f.title = h("input"), h("label", {}, "Severity"), f.severity = h("select", {}, state.severities.map(s => h("option", {}, s))),
      h("label", {}, "Affected"), f.affected = h("input"), h("label", {}, "Description"), f.description = h("textarea", { rows: 4 }),
      h("label", {}, "Recommendation"), f.recommendation = h("textarea", { rows: 2 }),
      h("button", { class: "primary", style: "margin-top:1rem", onclick: async () => {
        try { await api("/findings", { method: "POST", body: Object.fromEntries(Object.entries(f).map(([k, el]) => [k, el.value])) }); go(); } catch (x) { msg.replaceChildren(errBox(x)); } } }, "Add"), msg));
  },

  async reports(root) {
    root.append(h("h2", {}, "Reports"));
    if (!state.engagement) { root.append(h("p", { class: "muted" }, "Activate an engagement first.")); return; }
    const msg = h("p");
    root.append(h("div", { class: "card" }, ["html", "md", "json", "csv", "pdf"].map(fmt => h("button", { style: "margin-right:.4rem", onclick: async () => {
      try { const r = await api("/report", { method: "POST", body: { format: fmt } }); msg.replaceChildren(h("span", { class: "ok" }, "Wrote " + r.filename)); go(); } catch (x) { msg.replaceChildren(errBox(x)); } } }, fmt)), msg));
    const rs = await api("/reports");
    root.append(h("table", {}, h("tr", {}, h("th", {}, "File"), h("th", {}, "Size")), ...rs.map(r => h("tr", {}, h("td", {}, h("a", { href: "/api/reports/" + encodeURIComponent(r.filename), target: "_blank", rel: "noopener" }, r.filename)), h("td", {}, r.size)))));
  },

  async audit(root) {
    root.append(h("h2", {}, "Audit log"));
    if (!state.engagement) { root.append(h("p", { class: "muted" }, "Activate an engagement first.")); return; }
    const a = await api("/audit?tail=300");
    root.append(h("p", { class: a.ok ? "ok" : "bad" }, (a.ok ? "Chain intact: " : "CHAIN BROKEN: ") + a.message));
    root.append(h("table", {}, h("tr", {}, ["#", "Time (UTC)", "Actor", "Action", "Detail"].map(x => h("th", {}, x))),
      ...a.records.slice().reverse().map(r => h("tr", {}, h("td", {}, r.seq), h("td", {}, r.ts), h("td", {}, r.actor), h("td", {}, r.action), h("td", {}, r.detail)))));
  },
};

function stream(id, out, msg) {
  if (es) es.close();
  es = new EventSource(`/api/jobs/${id}/stream`);
  es.onmessage = ev => { out.append(document.createTextNode(JSON.parse(ev.data) + "\n")); out.scrollTop = out.scrollHeight; };
  es.addEventListener("end", ev => {
    es.close(); const d = JSON.parse(ev.data);
    msg.replaceChildren(h("p", { class: d.status === "done" ? "ok" : "warn" }, `Finished: ${d.status}` + ((d.summary.findings || []).length ? ` — ${d.summary.findings.length} finding(s) recorded` : "")));
    refresh();
  });
  es.onerror = () => { /* browser retries automatically using Last-Event-ID */ };
}

async function go() {
  if (es) { es.close(); es = null; }
  try { await refresh(); } catch (e) { $("#view").replaceChildren(errBox(e)); return; }
  const name = location.hash.slice(1) || "dashboard";
  const root = $("#view"); root.replaceChildren();
  try { await (views[name] || views.dashboard)(root); } catch (e) { root.append(errBox(e)); }
}
window.addEventListener("hashchange", go);
go();
