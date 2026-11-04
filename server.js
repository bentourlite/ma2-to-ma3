"use strict";
// MA2 to MA3 Fixture Converter: login-protected site with an admin panel for invite links.
const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const path = require("node:path");
const fs = require("node:fs");
const { DatabaseSync } = require("node:sqlite");
const { page, esc } = require("./views/layout");

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const INVITE_DAYS = Number(process.env.INVITE_DAYS || 7);
const SESSION_DAYS = 30;
fs.mkdirSync(DATA_DIR, { recursive: true });

/* ---------- database ---------- */
const db = new DatabaseSync(path.join(DATA_DIR, "app.db"));
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL COLLATE NOCASE, name TEXT NOT NULL,
    password_hash TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0, disabled INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL, last_login INTEGER);
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS invites (
    id INTEGER PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, note TEXT, make_admin INTEGER NOT NULL DEFAULT 0,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    used_by INTEGER REFERENCES users(id) ON DELETE SET NULL, used_at INTEGER, revoked INTEGER NOT NULL DEFAULT 0);
  PRAGMA foreign_keys = ON;
`);
const now = () => Date.now();
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const newToken = () => crypto.randomBytes(32).toString("base64url");

// bootstrap the first admin from environment variables
(function bootstrap() {
  const count = db.prepare("SELECT COUNT(*) AS n FROM users").get().n;
  const email = process.env.ADMIN_EMAIL, pw = process.env.ADMIN_PASSWORD;
  if (count === 0) {
    if (!email || !pw) { console.warn("No users yet. Set ADMIN_EMAIL and ADMIN_PASSWORD to create the first admin."); return; }
    db.prepare("INSERT INTO users (email, name, password_hash, is_admin, created_at) VALUES (?, ?, ?, 1, ?)")
      .run(email.trim(), process.env.ADMIN_NAME || "Admin", bcrypt.hashSync(pw, 12), now());
    console.log(`Created admin ${email}`);
  }
})();

/* ---------- app ---------- */
const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use((req, res, next) => {
  res.set({ "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin" });
  next();
});

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || "").split(";").forEach(p => { const i = p.indexOf("="); if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); });
  return out;
}
function setSession(res, req, userId) {
  const token = newToken();
  db.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)").run(sha(token), userId, now() + SESSION_DAYS * 864e5);
  db.prepare("UPDATE users SET last_login = ? WHERE id = ?").run(now(), userId);
  res.cookie("sid", token, { httpOnly: true, sameSite: "lax", secure: req.secure, maxAge: SESSION_DAYS * 864e5, path: "/" });
}
// load user from session cookie
app.use((req, res, next) => {
  const sid = parseCookies(req).sid;
  if (sid) {
    const row = db.prepare(`SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ? AND u.disabled = 0`).get(sha(sid), now());
    if (row) req.user = row;
  }
  next();
});
// CSRF: SameSite=Lax cookies plus an Origin/Referer check on every POST
app.use((req, res, next) => {
  if (req.method !== "POST") return next();
  const origin = req.get("origin") || req.get("referer") || "";
  const host = req.get("host");
  try { if (origin && new URL(origin).host === host) return next(); } catch {}
  res.status(403).send(page("Request blocked", `<p>This form was sent from another site, so it was blocked. Go back and try again.</p>`));
});

const requireUser = (req, res, next) => req.user ? next() : res.redirect("/login?next=" + encodeURIComponent(req.originalUrl));
const requireAdmin = (req, res, next) => !req.user ? res.redirect("/login") : req.user.is_admin ? next() : res.status(403).send(page("Admins only", `<p>Only admins can open this page. <a href="/">Back to the converter</a></p>`, req.user));

// simple login throttling per IP
const attempts = new Map();
function throttled(ip) {
  const a = attempts.get(ip) || { n: 0, t: now() };
  if (now() - a.t > 15 * 60e3) { a.n = 0; a.t = now(); }
  attempts.set(ip, a);
  return a.n >= 10;
}

/* ---------- auth pages ---------- */
const loginForm = (msg = "", email = "", next = "/") => page("Sign in", `
  <form method="post" action="/login" class="card narrow">
    <h1>Sign in</h1>
    ${msg ? `<p class="err">${esc(msg)}</p>` : ""}
    <input type="hidden" name="next" value="${esc(next)}">
    <label>Email<input type="email" name="email" id="email" value="${esc(email)}" autocomplete="username" required autofocus></label>
    <label>Password<input type="password" name="password" id="password" autocomplete="current-password" required></label>
    <button class="primary" type="submit">Sign in</button>
    <p class="muted">Access is by invitation. Ask your admin for an invite link.</p>
  </form>`);

app.get("/login", (req, res) => req.user ? res.redirect("/") : res.send(loginForm("", "", req.query.next || "/")));
app.post("/login", (req, res) => {
  const ip = req.ip;
  const next = typeof req.body.next === "string" && req.body.next.startsWith("/") && !req.body.next.startsWith("//") ? req.body.next : "/";
  if (throttled(ip)) return res.status(429).send(loginForm("Too many attempts. Wait 15 minutes and try again."));
  const email = String(req.body.email || "").trim();
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  if (!user || user.disabled || !bcrypt.compareSync(String(req.body.password || ""), user.password_hash)) {
    attempts.get(ip).n++;
    return res.status(401).send(loginForm("That email and password don't match an active account.", email, next));
  }
  attempts.delete(ip);
  setSession(res, req, user.id);
  res.redirect(next);
});
app.post("/logout", (req, res) => {
  const sid = parseCookies(req).sid;
  if (sid) db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(sha(sid));
  res.clearCookie("sid", { path: "/" });
  res.redirect("/login");
});

/* ---------- invites ---------- */
function findInvite(token) {
  const inv = db.prepare("SELECT * FROM invites WHERE token_hash = ?").get(sha(String(token || "")));
  if (!inv) return [null, "This invite link isn't valid. Ask your admin for a new one."];
  if (inv.revoked) return [null, "This invite link was cancelled. Ask your admin for a new one."];
  if (inv.used_at) return [null, "This invite link has already been used. Sign in instead, or ask for a new link."];
  if (inv.expires_at < now()) return [null, "This invite link has expired. Ask your admin for a new one."];
  return [inv, null];
}
const signupForm = (token, inv, msg = "", v = {}) => page("Create your account", `
  <form method="post" action="/invite/${esc(token)}" class="card narrow">
    <h1>Create your account</h1>
    <p class="muted">You've been invited to the MA2 to MA3 Fixture Converter${inv.note ? ` (${esc(inv.note)})` : ""}.</p>
    ${msg ? `<p class="err">${esc(msg)}</p>` : ""}
    <label>Name<input type="text" name="name" id="name" value="${esc(v.name || "")}" autocomplete="name" required maxlength="80"></label>
    <label>Email<input type="email" name="email" id="email" value="${esc(v.email || "")}" autocomplete="email" required maxlength="200"></label>
    <label>Password<input type="password" name="password" id="password" autocomplete="new-password" required minlength="10"></label>
    <p class="muted">At least 10 characters.</p>
    <button class="primary" type="submit">Create account</button>
  </form>`);

app.get("/invite/:token", (req, res) => {
  const [inv, err] = findInvite(req.params.token);
  if (!inv) return res.status(410).send(page("Invite link", `<div class="card narrow"><h1>Invite link</h1><p>${esc(err)}</p><p><a href="/login">Go to sign in</a></p></div>`));
  res.send(signupForm(req.params.token, inv));
});
app.post("/invite/:token", (req, res) => {
  const [inv, err] = findInvite(req.params.token);
  if (!inv) return res.status(410).send(page("Invite link", `<div class="card narrow"><p>${esc(err)}</p></div>`));
  const name = String(req.body.name || "").trim(), email = String(req.body.email || "").trim(), pw = String(req.body.password || "");
  const v = { name, email };
  if (!name || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).send(signupForm(req.params.token, inv, "Enter your name and a valid email address.", v));
  if (pw.length < 10) return res.status(400).send(signupForm(req.params.token, inv, "Use a password of at least 10 characters.", v));
  if (db.prepare("SELECT 1 FROM users WHERE email = ?").get(email)) return res.status(409).send(signupForm(req.params.token, inv, "An account with that email already exists. Sign in instead.", v));
  const r = db.prepare("INSERT INTO users (email, name, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?, ?)").run(email, name, bcrypt.hashSync(pw, 12), inv.make_admin, now());
  db.prepare("UPDATE invites SET used_by = ?, used_at = ? WHERE id = ?").run(r.lastInsertRowid, now(), inv.id);
  setSession(res, req, r.lastInsertRowid);
  res.redirect("/");
});

/* ---------- admin ---------- */
const fmt = t => t ? new Date(t).toISOString().slice(0, 16).replace("T", " ") + " UTC" : "";
function adminPage(req, flash = "") {
  const users = db.prepare("SELECT * FROM users ORDER BY created_at").all();
  const invites = db.prepare(`SELECT i.*, u.email AS used_email FROM invites i LEFT JOIN users u ON u.id = i.used_by ORDER BY i.created_at DESC LIMIT 100`).all();
  const status = i => i.revoked ? `<span class="pill">Cancelled</span>` : i.used_at ? `<span class="pill ok">Used by ${esc(i.used_email || "deleted user")}</span>` : i.expires_at < now() ? `<span class="pill">Expired</span>` : `<span class="pill live">Open until ${fmt(i.expires_at)}</span>`;
  return page("Admin", `
    ${flash}
    <section class="card">
      <h2>Create an invite link</h2>
      <form method="post" action="/admin/invites" class="row">
        <label>Who is it for? (optional)<input type="text" name="note" id="note" maxlength="120" placeholder="e.g. Sam, lighting programmer"></label>
        <label>Valid for<select name="days" id="days"><option value="1">1 day</option><option value="7" selected>7 days</option><option value="30">30 days</option></select></label>
        <label class="check"><input type="checkbox" name="make_admin" id="make_admin" value="1"> Make them an admin</label>
        <button class="primary" type="submit">Create link</button>
      </form>
      <p class="muted">Each link works once. Send it to the person yourself; it isn't emailed.</p>
    </section>
    <section class="card">
      <h2>Invites</h2>
      ${invites.length ? `<div class="tbl"><table><thead><tr><th>For</th><th>Created</th><th>Status</th><th></th></tr></thead><tbody>
      ${invites.map(i => `<tr><td>${esc(i.note || "")}${i.make_admin ? ` <span class="pill">Admin</span>` : ""}</td><td>${fmt(i.created_at)}</td><td>${status(i)}</td><td>${!i.revoked && !i.used_at && i.expires_at > now() ? `<form method="post" action="/admin/invites/${i.id}/revoke"><button type="submit">Cancel</button></form>` : ""}</td></tr>`).join("")}
      </tbody></table></div>` : `<p class="muted">No invites yet.</p>`}
    </section>
    <section class="card">
      <h2>Users</h2>
      <div class="tbl"><table><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Last sign-in</th><th></th></tr></thead><tbody>
      ${users.map(u => `<tr><td>${esc(u.name)}</td><td>${esc(u.email)}</td><td>${u.is_admin ? "Admin" : "User"}${u.disabled ? ` <span class="pill">Disabled</span>` : ""}</td><td>${fmt(u.last_login)}</td><td>${u.id === req.user.id ? `<span class="muted">You</span>` : `
        <form method="post" action="/admin/users/${u.id}/toggle"><button type="submit">${u.disabled ? "Enable" : "Disable"}</button></form>
        <form method="post" action="/admin/users/${u.id}/admin"><button type="submit">${u.is_admin ? "Remove admin" : "Make admin"}</button></form>`}</td></tr>`).join("")}
      </tbody></table></div>
    </section>`, req.user, true);
}
app.get("/admin", requireAdmin, (req, res) => res.send(adminPage(req)));
app.post("/admin/invites", requireAdmin, (req, res) => {
  const days = [1, 7, 30].includes(Number(req.body.days)) ? Number(req.body.days) : INVITE_DAYS;
  const token = newToken();
  db.prepare("INSERT INTO invites (token_hash, note, make_admin, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)")
    .run(sha(token), String(req.body.note || "").trim().slice(0, 120), req.body.make_admin ? 1 : 0, req.user.id, now(), now() + days * 864e5);
  const link = `${req.protocol}://${req.get("host")}/invite/${token}`;
  res.send(adminPage(req, `<section class="card flash"><h2>Invite link ready</h2><p>Copy this now. For security it won't be shown again.</p>
    <div class="copyrow"><input type="text" id="invite-link" value="${esc(link)}" readonly><button type="button" class="primary" onclick="const i=document.getElementById('invite-link');i.select();navigator.clipboard&&navigator.clipboard.writeText(i.value).then(()=>this.textContent='Copied',()=>{});">Copy</button></div></section>`));
});
app.post("/admin/invites/:id/revoke", requireAdmin, (req, res) => { db.prepare("UPDATE invites SET revoked = 1 WHERE id = ?").run(Number(req.params.id)); res.redirect("/admin"); });
app.post("/admin/users/:id/toggle", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (id !== req.user.id) { db.prepare("UPDATE users SET disabled = 1 - disabled WHERE id = ?").run(id); db.prepare("DELETE FROM sessions WHERE user_id = ?").run(id); }
  res.redirect("/admin");
});
app.post("/admin/users/:id/admin", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (id !== req.user.id) db.prepare("UPDATE users SET is_admin = 1 - is_admin WHERE id = ?").run(id);
  res.redirect("/admin");
});

/* ---------- account ---------- */
const accountPage = (req, msg = "", ok = false) => page("Your account", `
  <form method="post" action="/account/password" class="card narrow" style="margin-top:0">
    <h1>Change password</h1>
    ${msg ? `<p class="${ok ? "muted" : "err"}">${esc(msg)}</p>` : ""}
    <label>Current password<input type="password" name="current" id="current" autocomplete="current-password" required></label>
    <label>New password<input type="password" name="password" id="password" autocomplete="new-password" required minlength="10"></label>
    <p class="muted">At least 10 characters. Other devices are signed out.</p>
    <button class="primary" type="submit">Change password</button>
  </form>`, req.user, true);
app.get("/account", requireUser, (req, res) => res.send(accountPage(req)));
app.post("/account/password", requireUser, (req, res) => {
  if (!bcrypt.compareSync(String(req.body.current || ""), req.user.password_hash)) return res.status(400).send(accountPage(req, "Your current password is wrong."));
  const pw = String(req.body.password || "");
  if (pw.length < 10) return res.status(400).send(accountPage(req, "Use a password of at least 10 characters."));
  db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(bcrypt.hashSync(pw, 12), req.user.id);
  db.prepare("DELETE FROM sessions WHERE user_id = ?").run(req.user.id);
  setSession(res, req, req.user.id);
  res.send(accountPage(req, "Password changed.", true));
});

/* ---------- the converter ---------- */
const converterHtml = fs.readFileSync(path.join(__dirname, "public", "converter.html"), "utf8");
app.get("/", requireUser, (req, res) => {
  const bar = `<div style="display:flex;gap:12px;justify-content:flex-end;align-items:center;font:14px system-ui,sans-serif;padding:8px 16px;max-width:1240px;margin:0 auto">
    <a href="/account" style="color:inherit">${esc(req.user.name)}</a>${req.user.is_admin ? `<a href="/admin" style="color:inherit">Admin</a>` : ""}
    <form method="post" action="/logout" style="margin:0"><button type="submit" style="font:inherit;background:none;border:1px solid currentColor;border-radius:6px;padding:4px 10px;color:inherit;cursor:pointer">Sign out</button></form></div>`;
  res.set("Cache-Control", "no-store").send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="margin:0">${bar}${converterHtml}</body></html>`);
});
app.get("/healthz", (req, res) => res.send("ok"));

// tidy expired sessions hourly
setInterval(() => db.prepare("DELETE FROM sessions WHERE expires_at < ?").run(now()), 3600e3).unref();

app.listen(PORT, () => console.log(`Listening on ${PORT}`));
