import http.server
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from warrant import report  # noqa: E402
from warrant.engagement import Engagement, EngagementError  # noqa: E402
from warrant.runner import NoEngagement, RunContext, ScopeViolation, ToolRunner, ToolSpec  # noqa: E402
from warrant.scope import Scope, TargetError, parse_target  # noqa: E402
from warrant.tools import REGISTRY, builtin, parsers  # noqa: E402
from warrant.tools.external import NMAP_ALLOWED  # noqa: E402
from warrant.validate import Param, ValidationError, validate_params  # noqa: E402

FAKE_DNS = {"app.example.com": ["10.0.0.5"], "cdn.example.com": ["203.0.113.9"], "evil.test": ["10.0.0.99"]}


def resolver(host):
    return FAKE_DNS.get(host, [])


class Home(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.environ["WARRANT_HOME"] = self.tmp

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make(self, **kw):
        e = Engagement.create("t1", client="C", tester="T")
        for s in kw.get("scope", ["127.0.0.0/8", "10.0.0.0/24", "example.com"]):
            e.add_scope(s)
        for s in kw.get("exclude", []):
            e.add_scope(s, exclude=True)
        return e


class ScopeTests(unittest.TestCase):
    def test_rules(self):
        s = Scope(["10.0.0.0/24", "*.example.com"], ["10.0.0.99", "admin.example.com"], resolver=resolver)
        ok = lambda t: s.check(t).allowed  # noqa: E731
        self.assertTrue(ok("10.0.0.5"))
        self.assertTrue(ok("10.0.0.1-50"))
        self.assertTrue(ok("app.example.com"))
        self.assertTrue(ok("https://app.example.com/x?y=1"))
        self.assertTrue(ok("example.com"))
        self.assertFalse(ok("10.0.0.0/24"), "network overlapping an exclusion")
        self.assertFalse(ok("10.0.0.0/16"), "network larger than scope")
        self.assertFalse(ok("10.0.0.99"))
        self.assertFalse(ok("admin.example.com"))
        self.assertFalse(ok("evil.test"), "resolves into excluded address")
        self.assertFalse(ok("8.8.8.8"))
        self.assertFalse(ok("notexample.com"), "suffix without dot boundary")
        self.assertFalse(ok("unknown.invalid"))
        self.assertTrue(s.check("cdn.example.com").warnings, "third-party hosting warning")

    def test_injection_and_garbage(self):
        s = Scope(["10.0.0.0/24"])
        for bad in ["-oN /tmp/x", "10.0.0.5 -p-", "10.0.0.5;id", "$(id)", "", "999.1.1.1", "10.0.0.5\n6", "--script=x"]:
            self.assertFalse(s.check(bad).allowed, bad)

    def test_empty_scope_denies_unless_unscoped(self):
        self.assertFalse(Scope([]).check("10.0.0.5").allowed)
        d = Scope([], allow_unscoped=True).check("10.0.0.5")
        self.assertTrue(d.allowed and d.warnings)

    def test_parse_target(self):
        self.assertEqual(parse_target("10.0.0.5:8080").host, "10.0.0.5")
        self.assertEqual(parse_target("[::1]:80").host, "::1")
        self.assertEqual(parse_target("HTTP://Example.COM./a").host, "example.com")
        with self.assertRaises(TargetError):
            parse_target("a b")


class ValidationTests(unittest.TestCase):
    def test_flags_allowlist(self):
        p = Param("extra", "flags", allowed=NMAP_ALLOWED)
        self.assertEqual(validate_params([p], {"extra": "-sS -T4 -p 22,80 --top-ports=100"})[0]["extra"],
                         ["-sS", "-T4", "-p", "22,80", "--top-ports", "100"])
        for bad in ["-oN /tmp/x", "-iL hosts", "--script ./evil.nse", "--datadir /x", "-p ; id", "10.0.0.1", "-sS=1", "--script"]:
            with self.assertRaises(ValidationError, msg=bad):
                validate_params([p], {"extra": bad})

    def test_types(self):
        params = [Param("t", "target"), Param("n", "int", min=1, max=5), Param("c", "choice", choices=["a", "b"]),
                  Param("ports", "ports", required=False)]
        ok, targets = validate_params(params, {"t": "10.0.0.5", "n": "3", "c": "a", "ports": "22,80-90,U:53"})
        self.assertEqual((ok["n"], targets), (3, ["10.0.0.5"]))
        for bad in [{"t": "-x", "n": 1, "c": "a"}, {"t": "10.0.0.5", "n": 9, "c": "a"}, {"t": "10.0.0.5", "n": 1, "c": "z"},
                    {"t": "10.0.0.5", "n": 1, "c": "a", "ports": "70000"}, {"t": "10.0.0.5", "n": 1, "c": "a", "extra": 1}]:
            with self.assertRaises(ValidationError):
                validate_params(params, bad)

    def test_url_requires_http(self):
        with self.assertRaises(ValidationError):
            validate_params([Param("u", "url")], {"u": "file:///etc/passwd"})


class EngagementTests(Home):
    def test_audit_chain_detects_tampering(self):
        e = self.make()
        e.add_finding("T", "low")
        self.assertTrue(e.verify_audit()[0])
        lines = e.audit_path.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[2])
        rec["detail"] = "edited"
        lines[2] = json.dumps(rec, sort_keys=True)
        e.audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertFalse(e.verify_audit()[0])
        lines.pop(1)
        e.audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertFalse(e.verify_audit()[0])

    def test_findings_dedupe_and_validation(self):
        e = self.make()
        a = e.add_finding("X", "high", affected="h", source="s")
        b = e.add_finding("X", "high", affected="h", source="s", evidence=["e1"])
        self.assertIs(a, b)
        self.assertEqual(len(e.findings), 1)
        with self.assertRaises(EngagementError):
            e.add_finding("Y", "catastrophic")
        with self.assertRaises(EngagementError):
            Engagement.create("../evil")
        self.assertEqual(Engagement.load("t1").findings[0].evidence, ["e1"])

    def test_scope_item_validation(self):
        e = self.make()
        with self.assertRaises(EngagementError):
            e.add_scope("10.0.0.1; rm -rf /")


class RunnerTests(Home):
    def spec(self, code):
        return ToolSpec("fake", "Fake", "Test", "", [Param("target", "target")], binary=sys.executable,
                        build=lambda p, c: [c.binary, "-c", code, p["target"]])

    def test_scope_blocks_before_execution_and_is_audited(self):
        e = self.make()
        marker = Path(self.tmp) / "ran"
        r = ToolRunner(e, {"fake": self.spec(f"open({str(marker)!r},'w').write('x')")})
        with self.assertRaises(ScopeViolation):
            r.run("fake", {"target": "8.8.8.8"})
        self.assertFalse(marker.exists())
        self.assertTrue(any(x["action"] == "BLOCKED" for x in e.read_audit()))

    def test_runs_streams_and_records_evidence(self):
        e = self.make()
        lines = []
        r = ToolRunner(e, {"fake": self.spec("import sys; print('hello', sys.argv[1])")})
        res = r.run("fake", {"target": "127.0.0.1"}, on_line=lines.append)
        self.assertEqual((res.status, lines), ("done", ["hello 127.0.0.1"]))
        self.assertTrue(Path(res.output_file).exists())
        self.assertTrue(e.verify_audit()[0])

    def test_failure_timeout_and_cancel(self):
        e = self.make()
        r = ToolRunner(e, {"fake": self.spec("import sys; sys.exit(3)")})
        self.assertEqual(r.run("fake", {"target": "127.0.0.1"}).status, "failed")
        slow = self.spec("import time; time.sleep(30)")
        slow.timeout = 1
        t0 = time.time()
        self.assertEqual(ToolRunner(e, {"fake": slow}).run("fake", {"target": "127.0.0.1"}).status, "timeout")
        self.assertLess(time.time() - t0, 10)
        cancel = threading.Event()
        threading.Timer(0.8, cancel.set).start()
        slow.timeout = 60
        self.assertEqual(ToolRunner(e, {"fake": slow}).run("fake", {"target": "127.0.0.1"}, cancel=cancel).status, "cancelled")

    def test_requires_engagement(self):
        with self.assertRaises(NoEngagement):
            ToolRunner(None, REGISTRY)

    def test_unknown_param_rejected(self):
        e = self.make()
        with self.assertRaises(ValidationError):
            ToolRunner(e, REGISTRY).run("nmap", {"target": "127.0.0.1", "flags": "-oN x"})

    def test_nmap_argv(self):
        spec = REGISTRY["nmap"]
        clean, _ = validate_params(spec.params, {"target": "10.0.0.5", "profile": "quick", "ports": "22,80", "timing": 2,
                                                 "extra": "-Pn --open"})
        ctx = RunContext(spec, None, Path(self.tmp), "s", threading.Event())
        ctx.binary = "nmap"
        argv = spec.build(clean, ctx)
        self.assertEqual(argv[0], "nmap")
        self.assertNotIn("--top-ports", argv)
        self.assertIn("-T2", argv)
        self.assertNotIn("-T4", argv)
        self.assertEqual(argv[-1], "10.0.0.5")
        self.assertEqual(argv[argv.index("-p") + 1], "22,80")


NMAP_XML = """<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.5" addrtype="ipv4"/>
<hostnames><hostname name="srv.example.com"/></hostnames><ports>
<port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18"/>
<script id="http-vuln-cve2017-5638" output="VULNERABLE: Apache Struts CVE-2017-5638"/>
<script id="vulners" output="cpe:/a:nginx\n    CVE-2021-23017    7.7    https://x\n    CVE-2019-9511  5.0  https://y"/></port>
<port protocol="tcp" portid="22"><state state="closed"/></port></ports></host></nmaprun>"""


class ParserTests(Home):
    def ctx(self, **paths):
        c = RunContext(REGISTRY["nmap"], None, Path(self.tmp), "s", threading.Event())
        c.paths = paths
        return c

    def test_nmap(self):
        p = Path(self.tmp) / "n.xml"
        p.write_text(NMAP_XML, encoding="utf-8")
        titles = {d["title"]: d for d in parsers.parse_nmap_xml(self.ctx(xml=p))}
        self.assertEqual(titles["Telnet exposed on 10.0.0.5 (srv.example.com)"]["severity"], "medium")
        self.assertIn("23/tcp  telnet", titles["Open ports on 10.0.0.5 (srv.example.com)"]["description"])
        nse = next(d for t, d in titles.items() if t.startswith("NSE http-vuln"))
        self.assertEqual((nse["severity"], nse["cve"]), ("high", "CVE-2017-5638"))
        v = next(d for t, d in titles.items() if t.startswith("Known CVEs"))
        self.assertEqual(v["severity"], "high")

    def test_nmap_rejects_entities(self):
        p = Path(self.tmp) / "bad.xml"
        p.write_text('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><nmaprun/>', encoding="utf-8")
        with self.assertRaises(ValueError):
            parsers.parse_nmap_xml(self.ctx(xml=p))

    def test_nuclei_ffuf_gobuster(self):
        j = Path(self.tmp) / "n.jsonl"
        j.write_text(json.dumps({"template-id": "t", "matched-at": "http://h/x", "info": {
            "name": "Thing", "severity": "high", "classification": {"cve-id": ["CVE-2020-1"], "cvss-score": 8.1}}}) + "\nnot json\n", encoding="utf-8")
        d = parsers.parse_nuclei(self.ctx(jsonl=j))
        self.assertEqual((d[0]["severity"], d[0]["cve"], d[0]["cvss"]), ("high", "CVE-2020-1", "8.1"))
        f = Path(self.tmp) / "f.json"
        f.write_text(json.dumps({"config": {"url": "http://h/FUZZ"}, "results": [
            {"url": "http://h/.git/HEAD", "status": 200}, {"url": "http://h/index.html", "status": 200}]}), encoding="utf-8")
        d = parsers.parse_ffuf(self.ctx(json=f))
        self.assertIn(".git/HEAD", d[0]["description"])
        self.assertNotIn("index.html", d[0]["description"])
        c = self.ctx()
        c.output = "/admin (Status: 200) [Size: 1]\n/about (Status: 200) [Size: 2]"
        c.spec = REGISTRY["gobuster_dir"]
        self.assertIn("/admin", parsers.parse_dirlines(c)[0]["description"])


class BuiltinTests(Home):
    @classmethod
    def setUpClass(cls):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/.env":
                    body = b"SECRET_KEY=abc123\nDEBUG=1\n"
                elif self.path == "/redir":
                    self.send_response(302)
                    self.send_header("Location", "http://127.0.0.1:1/other")
                    self.end_headers()
                    return
                elif self.path == "/":
                    body = b"hi"
                else:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Server", "Apache/2.4.1")
                self.send_header("Set-Cookie", "sid=1; Path=/")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Credentials", "true")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_headers_and_exposure_create_findings(self):
        e = self.make()
        r = ToolRunner(e, REGISTRY)
        res = r.run("headers_audit", {"url": f"http://127.0.0.1:{self.port}/"})
        titles = {f.title.split(" on ")[0] for f in res.findings}
        self.assertEqual(titles, {"Missing HTTP security headers", "Cookies missing security attributes",
                                  "Software version disclosure", "Permissive CORS with credentials"})
        res = r.run("web_exposure", {"url": f"http://127.0.0.1:{self.port}/"})
        self.assertEqual([f.title for f in res.findings], ["Exposed .env file on 127.0.0.1"])
        self.assertEqual(res.findings[0].severity, "high")

    def test_redirects_not_followed(self):
        status, headers, _ = builtin.http_get(f"http://127.0.0.1:{self.port}/redir")
        self.assertEqual((status, headers["Location"]), (302, "http://127.0.0.1:1/other"))

    def test_out_of_scope_url_never_requested(self):
        e = self.make(scope=["10.0.0.0/24"])
        with self.assertRaises(ScopeViolation):
            ToolRunner(e, REGISTRY).run("headers_audit", {"url": f"http://127.0.0.1:{self.port}/"})

    def test_hashid_and_wordlist(self):
        e = self.make()
        r = ToolRunner(e, REGISTRY)
        lines = []
        r.run("hashid", {"hash": "$2b$12$" + "a" * 53}, on_line=lines.append)
        self.assertTrue(any("bcrypt" in l and "3200" in l for l in lines))
        lines.clear()
        r.run("wordlist_gen", {"words": "acme,Summer", "max_entries": 500}, on_line=lines.append)
        path = lines[-1].split(" to ", 1)[1]
        words = Path(path).read_text(encoding="utf-8").split()
        self.assertIn("Acme2025", words)
        self.assertIn("Summer123!", words)


class ReportTests(Home):
    def test_html_escapes_everything_and_other_formats(self):
        e = self.make()
        e.client = "<script>alert(1)</script>"
        e.add_finding('<img src=x onerror=alert(1)>', "high", description="<b>d</b>", affected='"><svg>', recommendation="<i>r</i>")
        e.add_finding("=cmd|' /C calc'!A0", "low")
        doc = report.render_html(e)
        for raw in ("<script>alert", "<img src=x", "<svg>", "<b>d</b>", "<i>r</i>"):
            self.assertNotIn(raw, doc)
        self.assertIn("&lt;img src=x", doc)
        self.assertIn("'=cmd", report.render_csv(e))
        for fmt in ("html", "md", "json", "csv"):
            self.assertTrue(report.write_report(e, fmt).exists())
        with self.assertRaises(ValueError):
            report.write_report(e, "exe")


try:
    import flask  # noqa: F401
    HAVE_FLASK = True
except ImportError:
    HAVE_FLASK = False


@unittest.skipUnless(HAVE_FLASK, "flask not installed")
class WebTests(Home):
    def setUp(self):
        super().setUp()
        from warrant.web.server import create_app
        self.make()
        self.app = create_app(token="tok123")
        self.app.config["MANAGER"].activate(Engagement.load("t1"))
        self.c = self.app.test_client()
        self.c.set_cookie("warrant_token", "tok123")
        self.h = {"X-Warrant": "1"}

    def test_auth_host_origin_and_csrf(self):
        anon = self.app.test_client()
        self.assertEqual(anon.get("/api/state").status_code, 401)
        self.assertEqual(anon.get("/").status_code, 401)
        r = anon.get("/?token=tok123")
        self.assertEqual(r.status_code, 302)
        self.assertIn("HttpOnly", r.headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", r.headers["Set-Cookie"])
        self.assertEqual(self.c.get("/api/state", headers={"Host": "evil.example.net"}).status_code, 400)
        self.assertEqual(self.c.post("/api/scope", json={"item": "1.2.3.4"}).status_code, 400)           # no X-Warrant
        self.assertEqual(self.c.post("/api/scope", json={"item": "1.2.3.4"}, headers={**self.h, "Origin": "http://evil.example"}).status_code, 403)
        self.assertEqual(self.c.get("/api/state", headers={"Authorization": "Bearer nope"}).status_code, 200)  # cookie still valid
        self.assertEqual(self.app.test_client().get("/api/state", headers={"Authorization": "Bearer tok123"}).status_code, 200)
        self.assertIn("default-src 'self'", self.c.get("/api/state").headers["Content-Security-Policy"])

    def test_scope_enforced_for_target_only_params(self):
        """Regression: the old server skipped the scope check when only `target` (no `url`) was given."""
        r = self.c.post("/api/run", json={"tool": "nmap", "params": {"target": "8.8.8.8"}}, headers=self.h)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.get_json()["decisions"][0]["target"], "8.8.8.8")
        r = self.c.post("/api/run", json={"tool": "nmap", "params": {"target": "-oN /tmp/x"}}, headers=self.h)
        self.assertEqual(r.status_code, 400)
        r = self.c.post("/api/run", json={"tool": "headers_audit", "params": {"url": "http://8.8.8.8/"}}, headers=self.h)
        self.assertEqual(r.status_code, 403)

    def test_job_lifecycle_and_stream(self):
        r = self.c.post("/api/run", json={"tool": "hashid", "params": {"hash": "5f4dcc3b5aa765d61d8327deb882cf99"}}, headers=self.h)
        self.assertEqual(r.status_code, 202)
        jid = r.get_json()["id"]
        body = self.c.get(f"/api/jobs/{jid}/stream").get_data(as_text=True)
        self.assertIn("raw-md5", body)
        self.assertIn("event: end", body)
        self.assertEqual(self.c.get(f"/api/jobs/{jid}").get_json()["status"], "done")

    def test_findings_reports_audit(self):
        r = self.c.post("/api/findings", json={"title": "<b>x</b>", "severity": "low"}, headers=self.h)
        fid = r.get_json()["id"]
        self.assertEqual(self.c.patch(f"/api/findings/{fid}", json={"status": "confirmed"}, headers=self.h).get_json()["status"], "confirmed")
        self.assertEqual(self.c.patch(f"/api/findings/{fid}", json={"id": "F-999"}, headers=self.h).status_code, 400)
        name = self.c.post("/api/report", json={"format": "html"}, headers=self.h).get_json()["filename"]
        resp = self.c.get(f"/api/reports/{name}")
        self.assertIn("sandbox", resp.headers["Content-Security-Policy"])
        self.assertEqual(self.c.get("/api/reports/..%2Fengagement.json").status_code, 404)
        self.assertTrue(self.c.get("/api/audit").get_json()["ok"])


if __name__ == "__main__":
    unittest.main()
