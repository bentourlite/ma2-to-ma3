"use strict";
const esc = s => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

const CSS = `
:root { --bg:#f3f4f6; --panel:#fff; --ink:#16181d; --muted:#5d6470; --line:#d9dce2; --accent:#d97a00; --accent-ink:#fff; --ok:#1f8a4c; --err:#c0362c; --field:#f7f8fa; color-scheme: light }
@media (prefers-color-scheme: dark) { :root { --bg:#121418; --panel:#1b1e24; --ink:#e8eaee; --muted:#9aa1ad; --line:#2e333c; --accent:#ffa31a; --accent-ink:#1a1205; --ok:#4cc27f; --err:#ff6b5e; --field:#15171c; color-scheme: dark } }
* { box-sizing: border-box }
body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.45 "Barlow", system-ui, -apple-system, "Segoe UI", sans-serif; padding: 24px max(16px, env(safe-area-inset-left)) 48px }
.wrap { max-width: 980px; margin: 0 auto; display: grid; gap: 18px }
.top { display:flex; flex-wrap:wrap; gap:12px; justify-content:space-between; align-items:center }
.brand { font: 700 22px "Barlow Semi Condensed", "Arial Narrow", sans-serif; color: var(--ink); text-decoration:none }
.nav { display:flex; gap:12px; align-items:center }
.nav a { color: var(--ink) }
.card { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:18px; display:grid; gap:12px; min-width:0 }
.card.narrow { max-width: 420px; width: 100%; margin: 6vh auto 0 }
.card.flash { border-color: var(--accent) }
h1, h2 { font-family: "Barlow Semi Condensed", "Arial Narrow", sans-serif; margin: 0 }
h1 { font-size: 26px } h2 { font-size: 14px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted) }
label { display:grid; gap:4px; font-size:13px; color:var(--muted) }
label.check { display:flex; align-items:center; gap:8px; color: var(--ink) }
input[type=text], input[type=email], input[type=password], select { font: inherit; color: var(--ink); background: var(--field); border:1px solid var(--line); border-radius:6px; padding:8px 10px; width:100%; min-width:0 }
input:focus-visible, select:focus-visible, button:focus-visible, a:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px }
button { font: inherit; font-weight:600; font-size:14px; border-radius:7px; padding:8px 14px; cursor:pointer; border:1px solid var(--line); background:var(--panel); color:var(--ink) }
button.primary { background:var(--accent); color:var(--accent-ink); border-color:var(--accent) }
.row { display:grid; grid-template-columns: 2fr 1fr auto auto; gap: 12px; align-items: end }
@media (max-width: 720px) { .row { grid-template-columns: 1fr } }
.copyrow { display:flex; gap:8px } .copyrow input { font-family: ui-monospace, Menlo, monospace; font-size: 13px }
.muted { color: var(--muted); font-size: 13px; margin: 0 }
.err { color: var(--err); margin: 0 }
.tbl { overflow-x:auto }
table { border-collapse: collapse; width: 100%; font-size: 14px }
th, td { text-align:left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: middle }
th { font-size: 11px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted) }
td form { display: inline-block; margin: 0 4px 0 0 }
td button { padding: 4px 10px; font-size: 13px }
.pill { font-size: 12px; padding: 2px 8px; border-radius: 99px; border: 1px solid var(--line); color: var(--muted); white-space: nowrap }
.pill.ok { color: var(--ok) } .pill.live { color: var(--accent); border-color: var(--accent) }
`;

function page(title, body, user = null, wide = false) {
  const nav = user ? `<div class="nav"><a href="/">Converter</a>${user.is_admin ? `<a href="/admin">Admin</a>` : ""}<span class="muted">${esc(user.email)}</span>
    <form method="post" action="/logout" style="margin:0"><button type="submit">Sign out</button></form></div>` : "";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · MA2 to MA3 Fixture Converter</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Barlow+Semi+Condensed:wght@600;700&family=Barlow:wght@400;600&display=swap">
<style>${CSS}</style></head><body><div class="wrap">
${user || wide ? `<div class="top"><a class="brand" href="/">MA2 to MA3 Fixture Converter</a>${nav}</div>` : ""}
${body}</div></body></html>`;
}
module.exports = { page, esc };
