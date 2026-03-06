#!/usr/bin/env python3
"""
Penetration Testing Toolkit — Web Server
Serves a browser-based GUI for the toolkit, similar to SpiderFoot.

Usage:
    python3 server.py
    python3 server.py --port 8080
    python3 server.py --host 0.0.0.0   # expose on LAN (use with caution)

Then open: http://127.0.0.1:5000
"""

import argparse
import io
import json
import logging
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from flask import Flask, Response, jsonify, render_template, request, send_file, abort

# ── Toolkit imports ───────────────────────────────────────────────────────────
from Modules.engagement import (
    Engagement, list_engagements, load_engagement, ENGAGEMENTS_ROOT
)
from Modules.reporter import ReportGenerator, REPORTS_DIR

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s  %(levelname)-8s  %(message)s',
    datefmt='%H:%M:%S',
)
logger = logging.getLogger('toolkit.server')

# ── Wordlist detection ────────────────────────────────────────────────────────
_WORDLIST_CANDIDATES = [
    '/usr/share/seclists/Discovery/Web-Content/common.txt',
    '/usr/share/wordlists/dirb/common.txt',
    '/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt',
]
DEFAULT_WORDLIST = next((w for w in _WORDLIST_CANDIDATES if Path(w).exists()), '')


# ─────────────────────────────────────────────────────────────────────────────
# Job management
# ─────────────────────────────────────────────────────────────────────────────

class Job:
    """A background task with a streaming output queue."""

    def __init__(self, job_id: str, description: str, module: str):
        self.job_id      = job_id
        self.description = description
        self.module      = module
        self.queue: queue.Queue = queue.Queue()
        self.status      = 'running'   # running | done | error
        self.started_at  = datetime.now().isoformat()
        self.finished_at: Optional[str] = None
        self.return_code: Optional[int] = None
        self.output_lines: List[str] = []   # kept for history

    def to_dict(self) -> dict:
        return {
            'job_id':      self.job_id,
            'description': self.description,
            'module':      self.module,
            'status':      self.status,
            'started_at':  self.started_at,
            'finished_at': self.finished_at,
        }


class JobManager:
    """Manages background jobs and their output streams."""

    MAX_JOBS = 50   # keep last N jobs in memory

    def __init__(self):
        self._jobs: Dict[str, Job] = {}
        self._lock = threading.Lock()

    def create(self, description: str, module: str) -> Job:
        job_id = str(uuid.uuid4())[:8]
        job    = Job(job_id, description, module)
        with self._lock:
            self._jobs[job_id] = job
            # Prune old jobs
            if len(self._jobs) > self.MAX_JOBS:
                oldest = list(self._jobs.keys())[0]
                del self._jobs[oldest]
        return job

    def get(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)

    def list_recent(self, n: int = 10) -> List[dict]:
        with self._lock:
            return [j.to_dict() for j in list(self._jobs.values())[-n:]]

    def run_subprocess(self, job: Job, cmd: List[str]) -> None:
        """Run a subprocess, stream stdout → job queue, non-blocking."""
        def _worker():
            try:
                job.queue.put({'type': 'cmd', 'data': '$ ' + ' '.join(cmd)})
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    env=os.environ.copy(),
                )
                for line in proc.stdout:
                    clean = line.rstrip()
                    job.output_lines.append(clean)
                    job.queue.put({'type': 'output', 'data': clean})
                proc.wait()
                job.return_code = proc.returncode
                job.status      = 'done' if proc.returncode == 0 else 'error'
            except FileNotFoundError:
                msg = f"Tool not found: '{cmd[0]}'. Is it installed?"
                job.queue.put({'type': 'error', 'data': msg})
                job.status = 'error'
            except Exception as e:
                job.queue.put({'type': 'error', 'data': str(e)})
                job.status = 'error'
            finally:
                job.finished_at = datetime.now().isoformat()
                job.queue.put({'type': 'done', 'data': '', 'status': job.status})

        threading.Thread(target=_worker, daemon=True).start()

    def run_python(self, job: Job, func, *args, **kwargs) -> None:
        """Run a Python callable, capturing stdout → job queue, non-blocking."""
        def _worker():
            old_stdout = sys.stdout
            sys.stdout = _QueueWriter(job)
            try:
                func(*args, **kwargs)
                job.status = 'done'
            except Exception as e:
                job.queue.put({'type': 'error', 'data': str(e)})
                job.status = 'error'
            finally:
                sys.stdout = old_stdout
                job.finished_at = datetime.now().isoformat()
                job.queue.put({'type': 'done', 'data': '', 'status': job.status})

        threading.Thread(target=_worker, daemon=True).start()


class _QueueWriter:
    """Redirect print() output into a job queue."""

    def __init__(self, job: Job):
        self._job = job

    def write(self, text: str):
        for line in text.splitlines():
            if line.strip():
                self._job.output_lines.append(line)
                self._job.queue.put({'type': 'output', 'data': line})

    def flush(self):
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Command builders  (module → command args → subprocess cmd list)
# ─────────────────────────────────────────────────────────────────────────────

def _nmap_cmd(command: str, args: dict) -> List[str]:
    target = args.get('target', '')
    base   = ['nmap']
    if command == 'quick':       return base + ['-sV', '-sC', '-T4', '--top-ports', '1000', target]
    if command == 'full':        return base + ['-sV', '-sC', '-p-', '-T4', target]
    if command == 'stealth':     return base + ['-sS', '-T2', target]
    if command == 'aggressive':  return base + ['-A', '-T4', target]
    if command == 'vuln':        return base + ['--script', 'vuln', '-sV', target]
    if command == 'udp':         return base + ['-sU', '--top-ports', '100', target]
    if command == 'os':          return base + ['-O', target]
    if command == 'ports':
        ports = args.get('ports', '1-1024')
        return base + ['-sV', '-p', ports, target]
    if command == 'custom':
        flags = args.get('flags', '')
        return base + flags.split() + [target]
    return base + ['-sV', target]


def _osint_cmd(command: str, args: dict):
    target  = args.get('target', '')
    if command == 'whois':        return ['whois', target]
    if command == 'dig':
        rtype = args.get('record_type', 'A')
        return ['dig', '+short', target, rtype]
    if command == 'subfinder':    return ['subfinder', '-d', target, '-silent']
    if command == 'amass':        return ['amass', 'enum', '-d', target, '-passive']
    if command == 'dnsrecon':     return ['dnsrecon', '-d', target, '-t', args.get('type', 'std')]
    if command == 'theharvester':
        sources = args.get('sources', 'google,bing,linkedin')
        return ['theHarvester', '-d', target, '-b', sources, '-l', '200']
    return None   # handled as Python job


def _fuzzer_cmd(command: str, args: dict) -> List[str]:
    url      = args.get('url', '')
    wordlist = args.get('wordlist') or DEFAULT_WORDLIST
    threads  = str(args.get('threads', 50))
    codes    = args.get('status_codes', '200,204,301,302,307,401,403')
    ext      = args.get('extensions', 'php,html,txt,js,bak')

    if command == 'gobuster_dir':
        cmd = ['gobuster', 'dir', '-u', url, '-w', wordlist,
               '-t', threads, '-s', codes, '--no-error']
        if ext:
            cmd += ['-x', ext]
        return cmd
    if command == 'gobuster_dns':
        return ['gobuster', 'dns', '-d', args.get('target', url),
                '-w', wordlist, '-t', threads]
    if command == 'gobuster_vhost':
        return ['gobuster', 'vhost', '-u', url, '-w', wordlist,
                '-t', threads, '--append-domain']
    if command == 'ffuf':
        fuzz_url = url if 'FUZZ' in url else url.rstrip('/') + '/FUZZ'
        return ['ffuf', '-u', fuzz_url, '-w', wordlist,
                '-t', threads, '-mc', codes, '-of', 'json']
    if command == 'feroxbuster':
        return ['feroxbuster', '-u', url, '-w', wordlist,
                '-t', threads, '--no-state']
    return []


def _iptrace_cmd(command: str, args: dict) -> List[str]:
    target = args.get('target', '')
    if command == 'traceroute': return ['traceroute', target]
    if command == 'mtr':        return ['mtr', '--report', '--report-cycles', '3', target]
    if command == 'ping':       return ['ping', '-c', '5', target]
    if command == 'whois':      return ['whois', target]
    return ['traceroute', target]


def _vulnscan_cmd(command: str, args: dict) -> List[str]:
    target = args.get('target', '')
    if command == 'nikto':        return ['nikto', '-h', target]
    if command == 'nikto_quick':  return ['nikto', '-h', target, '-Tuning', '1234']
    if command == 'nmap_vuln':    return ['nmap', '--script', 'vuln', '-sV', target]
    if command == 'nmap_ssl':
        return ['nmap', '--script', 'ssl-enum-ciphers,ssl-cert', '-p', '443,8443', target]
    if command == 'headers':
        return ['curl', '-sI', '--max-time', '10', target]
    if command == 'ports':
        return ['nmap', '-p',
                '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443',
                '-sV', target]
    return ['nmap', '--script', 'vuln', target]


# ─────────────────────────────────────────────────────────────────────────────
# Flask application
# ─────────────────────────────────────────────────────────────────────────────

app           = Flask(__name__, template_folder='templates')
job_manager   = JobManager()
_active_eng: Optional[Engagement] = None


def _get_eng() -> Optional[Engagement]:
    return _active_eng


def _set_eng(eng: Optional[Engagement]):
    global _active_eng
    _active_eng = eng


# ── Helper ────────────────────────────────────────────────────────────────────

def _check_scope(target: str) -> tuple[bool, str]:
    """Returns (ok, error_msg). ok=True if no engagement or target is in scope."""
    eng = _get_eng()
    if eng is None:
        return True, ''
    if eng.is_in_scope(target):
        return True, ''
    return False, f"Target '{target}' is out of scope for engagement '{eng.name}'."


def _tool_status() -> dict:
    tools = ['nmap', 'nikto', 'gobuster', 'ffuf', 'feroxbuster',
             'subfinder', 'amass', 'dnsrecon', 'theHarvester', 'whois', 'dig',
             'traceroute', 'mtr']
    return {t: shutil.which(t) is not None for t in tools}


# ── Static / index ────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


# ── Status ────────────────────────────────────────────────────────────────────

@app.route('/api/status')
def api_status():
    eng = _get_eng()
    return jsonify({
        'engagement':    eng.name if eng else None,
        'client':        eng.client if eng else None,
        'finding_counts': eng.finding_counts if eng else {},
        'tools':         _tool_status(),
        'default_wordlist': DEFAULT_WORDLIST,
        'recent_jobs':   job_manager.list_recent(5),
    })


# ── Engagements ───────────────────────────────────────────────────────────────

@app.route('/api/engagements', methods=['GET'])
def api_list_engagements():
    names = list_engagements()
    result = []
    for n in sorted(names):
        e = load_engagement(n)
        if e:
            result.append({
                'name':    e.name,
                'client':  e.client,
                'tester':  e.tester,
                'started': e.start_date,
                'findings': sum(e.finding_counts.values()),
                'active':  _get_eng() and _get_eng().name == n,
            })
    return jsonify(result)


@app.route('/api/engagements', methods=['POST'])
def api_create_engagement():
    data = request.json or {}
    required = ['name', 'client', 'tester']
    for field in required:
        if not data.get(field):
            return jsonify({'error': f"'{field}' is required"}), 400

    import re
    if not re.match(r'^[a-zA-Z0-9_\-]+$', data['name']):
        return jsonify({'error': 'Name must be alphanumeric (dashes/underscores OK)'}), 400

    if (ENGAGEMENTS_ROOT / data['name']).exists():
        return jsonify({'error': f"Engagement '{data['name']}' already exists"}), 409

    scope = [s.strip() for s in data.get('scope', '').split(',') if s.strip()]
    eng   = Engagement(
        name        = data['name'],
        client      = data['client'],
        tester      = data['tester'],
        scope       = scope,
        excluded    = [],
        start_date  = datetime.now().strftime('%Y-%m-%d'),
        end_date    = data.get('end_date', ''),
        description = data.get('description', ''),
    )
    if not eng.save():
        return jsonify({'error': 'Failed to save engagement'}), 500

    _set_eng(eng)
    return jsonify({'ok': True, 'name': eng.name}), 201


@app.route('/api/engagements/<name>', methods=['GET'])
def api_get_engagement(name: str):
    eng = load_engagement(name)
    if not eng:
        return jsonify({'error': 'Not found'}), 404
    counts = eng.finding_counts
    return jsonify({
        'name':        eng.name,
        'client':      eng.client,
        'tester':      eng.tester,
        'start_date':  eng.start_date,
        'end_date':    eng.end_date,
        'description': eng.description,
        'scope':       eng.scope,
        'excluded':    eng.excluded,
        'finding_counts': counts,
        'audit_count': len(eng.audit_log),
        'active':      _get_eng() and _get_eng().name == name,
    })


@app.route('/api/engagements/<name>/activate', methods=['POST'])
def api_activate_engagement(name: str):
    eng = load_engagement(name)
    if not eng:
        return jsonify({'error': 'Not found'}), 404
    _set_eng(eng)
    return jsonify({'ok': True, 'active': name})


@app.route('/api/engagements/<name>/deactivate', methods=['POST'])
def api_deactivate_engagement(name: str):
    _set_eng(None)
    return jsonify({'ok': True})


@app.route('/api/engagements/<name>/scope', methods=['POST'])
def api_add_scope(name: str):
    eng = load_engagement(name)
    if not eng:
        return jsonify({'error': 'Not found'}), 404
    target = (request.json or {}).get('target', '').strip()
    if not target:
        return jsonify({'error': 'target required'}), 400
    if target not in eng.scope:
        eng.scope.append(target)
        eng.save()
        if _get_eng() and _get_eng().name == name:
            _get_eng().scope = eng.scope
    return jsonify({'ok': True, 'scope': eng.scope})


@app.route('/api/engagements/<name>/scope/<path:target>', methods=['DELETE'])
def api_remove_scope(name: str, target: str):
    eng = load_engagement(name)
    if not eng:
        return jsonify({'error': 'Not found'}), 404
    if target in eng.scope:
        eng.scope.remove(target)
        eng.save()
    return jsonify({'ok': True, 'scope': eng.scope})


@app.route('/api/engagements/<name>/findings', methods=['GET'])
def api_list_findings(name: str):
    eng = load_engagement(name)
    if not eng:
        return jsonify({'error': 'Not found'}), 404
    return jsonify([f.to_dict() for f in eng.findings_by_severity()])


@app.route('/api/engagements/<name>/findings', methods=['POST'])
def api_add_finding(name: str):
    eng  = load_engagement(name)
    if not eng:
        return jsonify({'error': 'Not found'}), 404
    data = request.json or {}
    if not data.get('title') or not data.get('severity'):
        return jsonify({'error': 'title and severity are required'}), 400

    finding = eng.add_finding(
        title          = data['title'],
        severity       = data['severity'],
        description    = data.get('description', ''),
        affected       = data.get('affected', ''),
        recommendation = data.get('recommendation', ''),
        cve            = data.get('cve'),
        source         = data.get('source', 'Web UI'),
    )
    # Keep in-memory engagement in sync
    if _get_eng() and _get_eng().name == name:
        _get_eng().findings.append(finding)

    return jsonify({'ok': True, 'id': finding.id}), 201


@app.route('/api/engagements/<name>/check', methods=['GET'])
def api_check_scope(name: str):
    eng    = load_engagement(name)
    target = request.args.get('target', '')
    if not eng or not target:
        return jsonify({'error': 'Bad request'}), 400
    return jsonify({'target': target, 'in_scope': eng.is_in_scope(target)})


# ── Job execution ─────────────────────────────────────────────────────────────

@app.route('/api/run', methods=['POST'])
def api_run():
    data    = request.json or {}
    module  = data.get('module', '')
    command = data.get('command', '')
    args    = data.get('args', {})

    # Scope check for relevant modules
    scope_target = args.get('target') or args.get('url', '').split('/')[2].split(':')[0] if args.get('url') else None
    if scope_target:
        ok, err = _check_scope(scope_target)
        if not ok:
            return jsonify({'error': err}), 403

    # Build subprocess command
    cmd = None
    if   module == 'nmap':     cmd = _nmap_cmd(command, args)
    elif module == 'osint':    cmd = _osint_cmd(command, args)
    elif module == 'fuzzer':   cmd = _fuzzer_cmd(command, args)
    elif module == 'vulnscan': cmd = _vulnscan_cmd(command, args)
    elif module == 'iptrace':  cmd = _iptrace_cmd(command, args)

    desc = f"{module}/{command} {scope_target or args.get('url', '')}"
    job  = job_manager.create(desc, module)

    if cmd:
        job_manager.run_subprocess(job, cmd)
    elif module == 'osint' and command == 'crtsh':
        # Python-based crtsh
        job_manager.run_python(job, _run_crtsh, args.get('target', ''))
    elif module == 'osint' and command == 'dns':
        job_manager.run_python(job, _run_dns, args.get('target', ''), args.get('record_type', 'ALL'))
    else:
        job.queue.put({'type': 'error', 'data': f"Unknown module/command: {module}/{command}"})
        job.queue.put({'type': 'done', 'data': '', 'status': 'error'})
        job.status = 'error'

    # Audit log
    eng = _get_eng()
    if eng:
        eng.audit(module, command, str(args))

    return jsonify({'job_id': job.job_id, 'description': job.description})


def _run_crtsh(domain: str):
    import requests as req
    print(f"Querying crt.sh for *.{domain} ...")
    try:
        r = req.get(f'https://crt.sh/?q=%.{domain}&output=json', timeout=20,
                    headers={'Accept': 'application/json'})
        data = r.json()
        subs = set()
        for entry in data:
            for name in entry.get('name_value', '').split('\n'):
                name = name.strip().lstrip('*.')
                if name and domain in name:
                    subs.add(name)
        print(f"\nFound {len(subs)} unique subdomains/certificates:\n")
        for s in sorted(subs):
            print(f"  {s}")
    except Exception as e:
        print(f"Error: {e}")


def _run_dns(domain: str, record_type: str = 'ALL'):
    import subprocess as sp
    types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA'] if record_type == 'ALL' else [record_type]
    print(f"DNS lookup: {domain}\n")
    for rtype in types:
        try:
            r = sp.run(['dig', '+short', domain, rtype],
                       capture_output=True, text=True, timeout=10)
            if r.stdout.strip():
                print(f"  {rtype:<8} {r.stdout.strip()}")
        except FileNotFoundError:
            import socket
            if rtype == 'A':
                try:
                    print(f"  A       {socket.gethostbyname(domain)}")
                except Exception:
                    print(f"  Could not resolve {domain}")
            break
        except Exception:
            pass


# ── SSE stream ────────────────────────────────────────────────────────────────

@app.route('/api/stream/<job_id>')
def api_stream(job_id: str):
    job = job_manager.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404

    def generate():
        while True:
            try:
                msg = job.queue.get(timeout=30)
                yield f"data: {json.dumps(msg)}\n\n"
                if msg.get('type') == 'done':
                    break
            except queue.Empty:
                # keepalive ping
                yield "data: {\"type\": \"ping\"}\n\n"

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control':  'no-cache',
            'X-Accel-Buffering': 'no',
        }
    )


@app.route('/api/jobs/<job_id>')
def api_job_status(job_id: str):
    job = job_manager.get(job_id)
    if not job:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({**job.to_dict(), 'output': job.output_lines[-100:]})


# ── Reports ───────────────────────────────────────────────────────────────────

@app.route('/api/report', methods=['POST'])
def api_generate_report():
    eng = _get_eng()
    if not eng:
        return jsonify({'error': 'No active engagement'}), 400

    fmt = (request.json or {}).get('format', 'html')
    gen = ReportGenerator(eng)

    try:
        if fmt == 'html':
            path = gen.generate_html()
        elif fmt == 'pdf':
            path = gen.generate_pdf()
            if not path:
                return jsonify({'error': 'weasyprint not installed — run: pip install weasyprint'}), 500
        elif fmt == 'json':
            path = gen.generate_json()
        elif fmt == 'csv':
            path = gen.generate_csv()
        else:
            return jsonify({'error': f'Unknown format: {fmt}'}), 400

        return jsonify({'ok': True, 'filename': path.name, 'path': str(path)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports')
def api_list_reports():
    if not REPORTS_DIR.exists():
        return jsonify([])
    files = sorted(REPORTS_DIR.iterdir(), key=lambda f: f.stat().st_mtime, reverse=True)
    return jsonify([
        {
            'filename': f.name,
            'size':     f.stat().st_size,
            'modified': datetime.fromtimestamp(f.stat().st_mtime).strftime('%Y-%m-%d %H:%M'),
        }
        for f in files if f.is_file()
    ])


@app.route('/api/reports/<filename>')
def api_serve_report(filename: str):
    path = REPORTS_DIR / filename
    if not path.exists() or not path.is_file():
        abort(404)
    return send_file(path)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Pentesters Toolkit Web Server')
    parser.add_argument('--host',   default='127.0.0.1',
                        help='Bind address (default: 127.0.0.1)')
    parser.add_argument('--port',   default=5000, type=int,
                        help='Port (default: 5000)')
    parser.add_argument('--no-browser', action='store_true',
                        help='Do not open browser automatically')
    parser.add_argument('--debug',  action='store_true',
                        help='Enable Flask debug mode')
    args = parser.parse_args()

    if args.host != '127.0.0.1':
        print('\n⚠  WARNING: Exposing the toolkit on a non-localhost address.')
        print('   Only do this on a trusted network. No authentication is enabled.\n')

    url = f'http://{args.host}:{args.port}'
    print(f'\n  🔒  Pentesters Toolkit v3.0')
    print(f'  ─────────────────────────────────────')
    print(f'  Web UI  →  {url}')
    print(f'  CLI     →  python3 toolkit.py')
    print(f'  ─────────────────────────────────────')
    print(f'  Press Ctrl+C to stop the server\n')

    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug,
        threaded=True,
        use_reloader=False,
    )


if __name__ == '__main__':
    main()
