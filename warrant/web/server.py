"""
Web GUI. A thin, authenticated JSON API over the same ToolRunner the CLI uses.

Hardening:
  * binds to loopback unless --allow-remote is given
  * random per-start token (cookie, SameSite=Strict, HttpOnly) required for everything
  * Host header allow-list (blocks DNS rebinding) and Origin check on state-changing requests
  * custom header required on state-changing requests
  * strict CSP; all tool output is rendered as text by the front end
"""

import hmac
import json
import re
import secrets
import threading
import time
import uuid
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, Response, abort, jsonify, make_response, redirect, request, send_from_directory

from .. import __version__
from ..engagement import SEVERITIES, STATUSES, Engagement, EngagementError, current_name, list_engagements, set_current
from ..report import write_report
from ..runner import NoEngagement, ScopeViolation, ToolMissing, ToolRunner
from ..tools import REGISTRY, describe_all
from ..validate import ValidationError

STATIC = Path(__file__).parent / "static"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
MAX_RUNNING = 4
MAX_JOBS = 100
CSP = "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"


class Job:
    def __init__(self, tool, params):
        self.id = uuid.uuid4().hex[:10]
        self.tool, self.params = tool, params
        self.status = "running"
        self.events = []
        self.cond = threading.Condition()
        self.cancel = threading.Event()
        self.started = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.finished = None
        self.summary = {}

    def push(self, line):
        with self.cond:
            self.events.append(line)
            self.cond.notify_all()

    def finish(self, status, summary):
        with self.cond:
            self.status, self.summary = status, summary
            self.finished = datetime.now(timezone.utc).isoformat(timespec="seconds")
            self.cond.notify_all()

    def to_dict(self, with_output=False):
        d = {"id": self.id, "tool": self.tool, "params": self.params, "status": self.status,
             "started": self.started, "finished": self.finished, "summary": self.summary}
        if with_output:
            d["output"] = self.events[-1000:]
        return d


class Manager:
    def __init__(self):
        self.lock = threading.RLock()
        self.active = None
        self.jobs = {}
        name = current_name()
        if name:
            try:
                self.active = Engagement.load(name)
            except EngagementError:
                pass

    def activate(self, eng):
        with self.lock:
            self.active = eng
        set_current(eng.name if eng else None)

    def start_job(self, tool_id, params):
        eng = self.active
        if eng is None:
            raise NoEngagement("No active engagement. Create or activate one first.")
        runner = ToolRunner(eng, REGISTRY)
        runner.prepare(tool_id, params)                       # raises ScopeViolation / ValidationError synchronously
        spec = REGISTRY[tool_id]
        if spec.binary and spec.resolve_binary() is None:
            raise ToolMissing(f"'{spec.binary}' is not installed. {spec.install}".strip())
        with self.lock:
            if sum(1 for j in self.jobs.values() if j.status == "running") >= MAX_RUNNING:
                raise RuntimeError("too many running jobs")
            job = Job(tool_id, params)
            self.jobs[job.id] = job
            while len(self.jobs) > MAX_JOBS:
                done = [k for k, j in self.jobs.items() if j.status != "running"]
                if not done:
                    break
                del self.jobs[done[0]]

        def work():
            try:
                res = runner.run(tool_id, params, on_line=job.push, cancel=job.cancel)
                job.finish(res.status, {"findings": [f.id for f in res.findings], "returncode": res.returncode,
                                        "duration": round(res.duration, 1)})
            except Exception as e:                           # noqa: BLE001
                job.push(f"[x] {type(e).__name__}: {e}")
                job.finish("failed", {})

        threading.Thread(target=work, daemon=True).start()
        return job


def create_app(token=None, manager=None):
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = 256 * 1024
    token = token or secrets.token_urlsafe(24)
    app.config["WARRANT_TOKEN"] = token
    mgr = manager or Manager()
    app.config["MANAGER"] = mgr

    def err(msg, code):
        return jsonify({"error": msg}), code

    # ---------- request gate ----------
    @app.before_request
    def gate():
        try:
            host = urlsplit("//" + (request.host or "")).hostname or ""
        except ValueError:
            host = ""
        allowed = LOOPBACK_HOSTS | set(app.config.get("EXTRA_HOSTS", ()))
        if host.lower() not in allowed:
            return err("invalid Host header", 400)
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if request.headers.get("X-Warrant") != "1":
                return err("missing X-Warrant header", 400)
            origin = request.headers.get("Origin")
            if origin and urlsplit(origin).netloc != request.host:
                return err("cross-origin request refused", 403)
        auth = request.headers.get("Authorization", "")
        candidates = [request.cookies.get("warrant_token", ""), auth[7:] if auth.startswith("Bearer ") else ""]
        if request.path == "/" and request.args.get("token"):
            if hmac.compare_digest(request.args["token"], token):
                resp = make_response(redirect("/"))
                resp.set_cookie("warrant_token", token, httponly=True, samesite="Strict")
                return resp
        if not any(hmac.compare_digest(c, token) for c in candidates):
            if request.path.startswith("/api/"):
                return err("unauthorized", 401)
            return Response("warrant: open the URL printed in the terminal (it contains the access token).",
                            401, mimetype="text/plain")

    @app.after_request
    def headers(resp):
        resp.headers.setdefault("Content-Security-Policy", CSP)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # ---------- static ----------
    @app.get("/")
    def index():
        return send_from_directory(STATIC, "index.html")

    @app.get("/static/<path:name>")
    def static_files(name):
        return send_from_directory(STATIC, name)

    # ---------- state ----------
    def eng_summary(e):
        return None if e is None else {"name": e.name, "client": e.client, "tester": e.tester, "includes": e.includes,
                                       "excludes": e.excludes, "counts": e.finding_counts(),
                                       "start_date": e.start_date, "end_date": e.end_date}

    @app.get("/api/state")
    def state():
        return jsonify({"version": __version__, "engagement": eng_summary(mgr.active), "engagements": list_engagements(),
                        "tools": describe_all(), "severities": SEVERITIES, "statuses": STATUSES})

    def need_eng():
        if mgr.active is None:
            abort(409, description="no active engagement")
        return mgr.active

    @app.errorhandler(409)
    @app.errorhandler(404)
    @app.errorhandler(413)
    def http_err(e):
        return err(getattr(e, "description", "error"), e.code)

    # ---------- engagements ----------
    @app.post("/api/engagements")
    def create_engagement():
        d = request.get_json(silent=True) or {}
        try:
            eng = Engagement.create(d.get("name", ""), client=d.get("client", ""), tester=d.get("tester", ""),
                                    description=d.get("description", ""), end_date=d.get("end_date", ""))
            for s in d.get("scope") or []:
                eng.add_scope(s)
            for s in d.get("exclude") or []:
                eng.add_scope(s, exclude=True)
        except EngagementError as e:
            return err(str(e), 400)
        mgr.activate(eng)
        return jsonify(eng_summary(eng)), 201

    @app.post("/api/engagements/<name>/activate")
    def activate(name):
        try:
            mgr.activate(Engagement.load(name))
        except EngagementError as e:
            return err(str(e), 404)
        return jsonify(eng_summary(mgr.active))

    @app.post("/api/deactivate")
    def deactivate():
        mgr.activate(None)
        return jsonify({"ok": True})

    # ---------- scope ----------
    @app.post("/api/scope")
    def scope_add():
        e = need_eng()
        d = request.get_json(silent=True) or {}
        try:
            norm = e.add_scope(d.get("item", ""), exclude=bool(d.get("exclude")))
        except EngagementError as ex:
            return err(str(ex), 400)
        return jsonify({"added": norm, "engagement": eng_summary(e)})

    @app.delete("/api/scope")
    def scope_rm():
        e = need_eng()
        return jsonify({"removed": e.remove_scope(request.args.get("item", "")), "engagement": eng_summary(e)})

    @app.get("/api/scope/check")
    def scope_check():
        e = need_eng()
        d = e.check(request.args.get("target", ""))
        return jsonify({"allowed": d.allowed, "reason": d.reason, "resolved": d.resolved, "warnings": d.warnings})

    # ---------- findings ----------
    @app.get("/api/findings")
    def findings():
        return jsonify([f.to_dict() for f in need_eng().sorted_findings()])

    @app.post("/api/findings")
    def finding_add():
        e = need_eng()
        d = request.get_json(silent=True) or {}
        try:
            f = e.add_finding(d.get("title", ""), d.get("severity", ""), d.get("description", ""), d.get("affected", ""),
                              d.get("recommendation", ""), d.get("cve", ""), d.get("cvss", ""), source="web")
        except EngagementError as ex:
            return err(str(ex), 400)
        return jsonify(f.to_dict()), 201

    @app.patch("/api/findings/<fid>")
    def finding_update(fid):
        e = need_eng()
        try:
            return jsonify(e.update_finding(fid, **(request.get_json(silent=True) or {})).to_dict())
        except EngagementError as ex:
            return err(str(ex), 400)

    @app.delete("/api/findings/<fid>")
    def finding_delete(fid):
        e = need_eng()
        try:
            e.delete_finding(fid)
        except EngagementError as ex:
            return err(str(ex), 404)
        return jsonify({"ok": True})

    # ---------- jobs ----------
    @app.post("/api/run")
    def run():
        d = request.get_json(silent=True) or {}
        try:
            job = mgr.start_job(d.get("tool", ""), d.get("params") or {})
        except ScopeViolation as e:
            return jsonify({"error": "out of scope", "decisions": [{"target": x.target, "reason": x.reason} for x in e.decisions]}), 403
        except (ValidationError, NoEngagement) as e:
            return err(str(e), 400)
        except ToolMissing as e:
            return err(str(e), 424)
        except RuntimeError as e:
            return err(str(e), 429)
        return jsonify(job.to_dict()), 202

    @app.get("/api/jobs")
    def jobs():
        return jsonify([j.to_dict() for j in sorted(mgr.jobs.values(), key=lambda j: j.started, reverse=True)])

    @app.get("/api/jobs/<jid>")
    def job_get(jid):
        j = mgr.jobs.get(jid)
        return jsonify(j.to_dict(with_output=True)) if j else err("not found", 404)

    @app.post("/api/jobs/<jid>/cancel")
    def job_cancel(jid):
        j = mgr.jobs.get(jid)
        if not j:
            return err("not found", 404)
        j.cancel.set()
        return jsonify({"ok": True})

    @app.get("/api/jobs/<jid>/stream")
    def job_stream(jid):
        j = mgr.jobs.get(jid)
        if not j:
            return err("not found", 404)
        try:
            pos = int(request.headers.get("Last-Event-ID") or request.args.get("from", 0))
        except ValueError:
            pos = 0

        def gen():
            nonlocal pos
            while True:
                with j.cond:
                    while pos >= len(j.events) and j.status == "running":
                        if not j.cond.wait(timeout=15):
                            yield ": keepalive\n\n"
                    chunk, pos_end, status = j.events[pos:pos + 200], min(len(j.events), pos + 200), j.status
                for i, line in enumerate(chunk):
                    yield f"id: {pos + i + 1}\ndata: {json.dumps(line)}\n\n"
                pos = pos_end
                if status != "running" and pos >= len(j.events):
                    yield f"event: end\ndata: {json.dumps(j.to_dict())}\n\n"
                    return

        return Response(gen(), mimetype="text/event-stream", headers={"X-Accel-Buffering": "no"})

    # ---------- reports / audit ----------
    @app.post("/api/report")
    def report():
        e = need_eng()
        fmt = (request.get_json(silent=True) or {}).get("format", "html")
        try:
            path = write_report(e, fmt)
        except (ValueError, RuntimeError) as ex:
            return err(str(ex), 400)
        return jsonify({"filename": path.name})

    @app.get("/api/reports")
    def reports():
        e = need_eng()
        files = sorted((p for p in e.reports_dir.iterdir() if p.is_file()), key=lambda p: p.stat().st_mtime, reverse=True)
        return jsonify([{"filename": p.name, "size": p.stat().st_size} for p in files])

    @app.get("/api/reports/<filename>")
    def report_file(filename):
        e = need_eng()
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", filename) or filename.startswith("."):
            return err("bad filename", 400)
        path = e.reports_dir / filename
        if not path.is_file():
            return err("not found", 404)
        resp = send_from_directory(e.reports_dir, filename, as_attachment=not filename.endswith(".html"))
        if filename.endswith(".html"):    # viewed inline but fully sandboxed
            resp.headers["Content-Security-Policy"] = "sandbox; default-src 'none'; style-src 'unsafe-inline'"
        return resp

    @app.get("/api/audit")
    def audit():
        e = need_eng()
        ok, msg = e.verify_audit()
        tail = min(int(request.args.get("tail", 200) or 200), 2000)
        return jsonify({"ok": ok, "message": msg, "records": e.read_audit()[-tail:]})

    return app


def serve(host, port, no_browser, allow_remote):
    loopback = host in ("127.0.0.1", "localhost", "::1")
    if not loopback and not allow_remote:
        print(f"Refusing to bind {host}: pass --allow-remote if you really want to expose this (no TLS; token auth only).")
        return 2
    app = create_app()
    if not loopback:
        app.config["EXTRA_HOSTS"] = {host.lower()}
        print("WARNING: remote access has no TLS. Use an SSH tunnel or VPN instead.")
    token = app.config["WARRANT_TOKEN"]
    url = f"http://{host}:{port}/?token={token}"
    print(f"\n  warrant {__version__} web GUI\n  Open: {url}\n  (the token changes every start; Ctrl+C stops the server)\n")
    if not no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    app.run(host=host, port=port, threaded=True, use_reloader=False)
    return 0
