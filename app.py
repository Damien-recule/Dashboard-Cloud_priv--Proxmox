#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NebTech Cloud Dashboard
-----------------------
Auteur : RECULE Damien
Date : 01/02/2026
-----------------------
Fonctionnalités :
- Authentification + 2FA
- Monitoring Proxmox (3 nœuds)
- Pastilles d’état (Terraform, Jenkins, Graylog, etc.)
- Logs Proxmox via SSH
- Liste des VMs + actions (start / stop / reset / delete)
- Ansible Automation (ping / maj)
- Fenêtre de déploiement Ansible (Apache2 pour l’instant)
- Intégration Graylog (via index.html)
- Déploiement de VMs via Terraform ÉPHÉMÈRE (1 VM ou groupe)
- Groupes de déploiement (stockés dans groups.json)
"""
Prérequis conseillés :
    pip install flask flask-socketio paramiko pyotp requests qrcode python-dotenv flask-wtf flask-limiter werkzeug

Variables d'environnement minimales :
    FLASK_SECRET_KEY=change_me_long_random
    ADMIN_USERNAME=admin
    ADMIN_PASSWORD_HASH=<hash werkzeug>
    TOTP_SECRET=<secret pyotp persistant>

    PVE_TOKEN_ID=root@pam!dashboard
    PVE_SECRET=<token_secret>
    PVE_ENDPOINT_NODE=pve-001

    PVE_001_IP=192.168.1.122
    PVE_002_IP=192.168.1.187
    PVE_003_IP=192.168.1.68

    ANSIBLE_HOST=192.168.1.27
    ANSIBLE_SSH_USER=svc-ansible
    VM_SSH_USER=svc-vm
    VM_SSH_PASSWORD=<mot_de_passe_ou_mieux_cle_ssh>

    TERRAFORM_PVE_USERNAME=root@pam
    TERRAFORM_PVE_PASSWORD=<mot_de_passe>
"""

from __future__ import annotations

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    flash,
    jsonify,
    send_file,
    abort,
)
from flask_socketio import SocketIO, emit
from flask_wtf import CSRFProtect
from flask_wtf.csrf import validate_csrf, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash

from functools import wraps
from ipaddress import ip_address
import io
import json
import logging
import os
import platform
import re
import secrets
import shutil
import subprocess
import tempfile
import time

import paramiko
import pyotp
import qrcode
import requests
import urllib3

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass


# -------------------------------------------------------------------
# LOGGING
# -------------------------------------------------------------------
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("nebtech-dashboard")


# -------------------------------------------------------------------
# HELPERS CONFIG
# -------------------------------------------------------------------
def env_required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Variable d'environnement manquante : {name}")
    return value


def env_default(name: str, default: str) -> str:
    return os.getenv(name, default)


def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def is_production() -> bool:
    return os.getenv("APP_ENV", "production").lower() == "production"


# -------------------------------------------------------------------
# FLASK APP
# -------------------------------------------------------------------
app = Flask(__name__)

app.secret_key = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)

app.config.update(
    SESSION_COOKIE_SECURE=is_production(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=env_int("SESSION_LIFETIME_SECONDS", 3600),
    WTF_CSRF_TIME_LIMIT=3600,
)

csrf = CSRFProtect(app)

socketio = SocketIO(
    app,
    cors_allowed_origins=os.getenv("SOCKETIO_CORS_ORIGINS", "*"),
    async_mode="threading",
)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "60 per hour"],
)

SSH_SESSIONS: dict[str, dict] = {}


# -------------------------------------------------------------------
# SÉCURITÉ / AUTH
# -------------------------------------------------------------------
ADMIN_USERNAME = env_default("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "")
TOTP_SECRET = os.getenv("TOTP_SECRET", "")

if not ADMIN_PASSWORD_HASH:
    logger.warning("ADMIN_PASSWORD_HASH absent : le login sera impossible.")
if not TOTP_SECRET:
    logger.warning("TOTP_SECRET absent : la 2FA sera impossible après redémarrage.")


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            if request.path.startswith("/api") or request.is_json:
                return jsonify({"success": False, "error": "authentification requise"}), 401
            return redirect("/login")
        return fn(*args, **kwargs)
    return wrapper


def validate_node(node: str) -> bool:
    return node in PVE_NODES


def validate_vmid(vmid) -> int | None:
    try:
        vmid_int = int(vmid)
        if 1 <= vmid_int <= 999999999:
            return vmid_int
    except (TypeError, ValueError):
        pass
    return None


def validate_ip(value: str) -> str | None:
    try:
        return str(ip_address(value))
    except Exception:
        return None


def validate_name(value: str, max_len: int = 64) -> str:
    value = (value or "").strip()
    value = re.sub(r"[^a-zA-Z0-9_.-]", "-", value)
    return value[:max_len] or "vm-demo"


def safe_int(value, default: int, min_value: int, max_value: int) -> int:
    try:
        value_int = int(value)
        return max(min_value, min(value_int, max_value))
    except Exception:
        return default


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    logger.warning("CSRF refusé depuis %s : %s", request.remote_addr, e.description)
    return jsonify({"success": False, "error": "CSRF token invalide ou manquant"}), 400


# -------------------------------------------------------------------
# CONFIG PROXMOX
# -------------------------------------------------------------------
VERIFY_TLS = os.getenv("PVE_VERIFY_TLS", "true").lower() == "true"
PVE_CA_BUNDLE = os.getenv("PVE_CA_BUNDLE")

if not VERIFY_TLS:
    urllib3.disable_warnings()
    logger.warning("PVE_VERIFY_TLS=false : validation TLS désactivée.")

PVE_NODES = {
    "pve-001": {"ip": env_default("PVE_001_IP", "192.168.1.122"), "name": "pve-001"},
    "pve-002": {"ip": env_default("PVE_002_IP", "192.168.1.187"), "name": "pve-002"},
    "pve-003": {"ip": env_default("PVE_003_IP", "192.168.1.68"), "name": "pve-003"},
}

PVE_HOSTS = {node: data["ip"] for node, data in PVE_NODES.items()}

PVE_TOKEN_ID = env_default("PVE_TOKEN_ID", "")
PVE_SECRET = env_default("PVE_SECRET", "")

HEADERS_PVE = {
    "Authorization": f"PVEAPIToken={PVE_TOKEN_ID}={PVE_SECRET}"
}


def pve_verify_value():
    if not VERIFY_TLS:
        return False
    return PVE_CA_BUNDLE or True


# -------------------------------------------------------------------
# TEMPLATES Proxmox
# -------------------------------------------------------------------
TEMPLATES_INFO = {
    "tpl_200": {"template_id": 200, "name": "Debian 13 Base"},
    "tpl_201": {"template_id": 201, "name": "Windows Server 2022 Base"},
    "tpl_202": {"template_id": 202, "name": "Windows 11 Base"},
    "tpl_203": {"template_id": 203, "name": "Ubuntu Base"},
}


# -------------------------------------------------------------------
# GROUPES DE DÉPLOIEMENT
# -------------------------------------------------------------------
GROUPS_FILE = env_default(
    "GROUPS_FILE",
    "/etc/terraform/cloud-project/environments/production/groups.json",
)

DEFAULT_GROUPS = {
    "Base": ["tpl_200", "tpl_201", "tpl_202", "tpl_203"],
}


def load_groups():
    if os.path.exists(GROUPS_FILE):
        try:
            with open(GROUPS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception as e:
            logger.error("Erreur lecture groups.json: %s", e)
    return DEFAULT_GROUPS.copy()


def save_groups(groups):
    try:
        os.makedirs(os.path.dirname(GROUPS_FILE), exist_ok=True)
        with open(GROUPS_FILE, "w", encoding="utf-8") as f:
            json.dump(groups, f, indent=2)
    except Exception as e:
        logger.error("Erreur sauvegarde groupes: %s", e)


DEPLOYMENT_GROUPS = load_groups()


# -------------------------------------------------------------------
# PING & MONITORING PROXMOX
# -------------------------------------------------------------------
def ping_ms(ip: str):
    try:
        start = time.time()
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", "-w", "1000", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]

        out = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )

        if out.returncode == 0:
            return round((time.time() - start) * 1000, 1)

    except Exception as e:
        logger.warning("Ping error %s: %s", ip, e)

    return None


@app.route("/monitor/<node>")
@login_required
def api_monitor(node):
    return jsonify(get_pve_stats(node))


def get_pve_stats(node):
    if node not in PVE_NODES:
        return {"online": False}

    ip = PVE_NODES[node]["ip"]
    name = PVE_NODES[node]["name"]
    latency = ping_ms(ip)

    try:
        r = requests.get(
            f"https://{ip}:8006/api2/json/nodes/{name}/status",
            headers=HEADERS_PVE,
            verify=pve_verify_value(),
            timeout=4,
        )
        r.raise_for_status()

        data = r.json().get("data", {})

        cpu = round(float(data.get("cpu", 0)) * 100, 1)

        mem = float(data.get("mem", 0))
        maxmem = float(data.get("maxmem") or 1)
        ram = round((mem / maxmem) * 100, 1) if maxmem else 0

        disk = 0
        rootfs = data.get("rootfs")
        if isinstance(rootfs, dict):
            used = float(rootfs.get("used", 0))
            total = float(rootfs.get("total", 1))
            if total > 0:
                disk = round((used / total) * 100, 1)

        r2 = requests.get(
            f"https://{ip}:8006/api2/json/nodes/{name}/qemu",
            headers=HEADERS_PVE,
            verify=pve_verify_value(),
            timeout=3,
        )
        r2.raise_for_status()
        vms = r2.json().get("data", [])

        return {
            "online": True,
            "ping": latency,
            "cpu": cpu,
            "ram": ram,
            "disk": disk,
            "vm": len(vms),
        }

    except Exception as e:
        logger.warning("API Proxmox error %s: %s", node, e)
        return {"online": False, "ping": latency}


# -------------------------------------------------------------------
# VM LIST & ACTIONS
# -------------------------------------------------------------------
def list_vms(node):
    if node not in PVE_NODES:
        return []

    ip = PVE_NODES[node]["ip"]
    name = PVE_NODES[node]["name"]

    try:
        r = requests.get(
            f"https://{ip}:8006/api2/json/nodes/{name}/qemu",
            headers=HEADERS_PVE,
            verify=pve_verify_value(),
            timeout=4,
        )
        r.raise_for_status()
        return r.json().get("data", [])
    except Exception as e:
        logger.warning("Erreur list_vms %s: %s", node, e)
        return []


def vm_action(node, vmid, action):
    if node not in PVE_NODES:
        return {"success": False, "error": "node inconnu"}

    vmid_int = validate_vmid(vmid)
    if vmid_int is None:
        return {"success": False, "error": "vmid invalide"}

    if action not in ["start", "stop", "reset"]:
        return {"success": False, "error": "action invalide"}

    ip = PVE_NODES[node]["ip"]
    name = PVE_NODES[node]["name"]

    try:
        r = requests.post(
            f"https://{ip}:8006/api2/json/nodes/{name}/qemu/{vmid_int}/status/{action}",
            headers=HEADERS_PVE,
            verify=pve_verify_value(),
            timeout=4,
        )
        r.raise_for_status()
        logger.info("VM action: node=%s vmid=%s action=%s user=%s", node, vmid_int, action, session.get("user"))
        return {"success": True}
    except Exception as e:
        logger.warning("VM action error: %s", e)
        return {"success": False, "error": str(e)}


@app.route("/vms/<node>")
@login_required
def api_list_vms(node):
    if node not in PVE_NODES:
        return jsonify({"error": "node inconnu"}), 400
    return jsonify(list_vms(node))


@app.route("/vm/<node>/<vmid>/<action>", methods=["POST"])
@login_required
def api_vm(node, vmid, action):
    return jsonify(vm_action(node, vmid, action))


@app.route("/vm/<node>/<vmid>/delete", methods=["POST"])
@login_required
def api_vm_delete(node, vmid):
    if node not in PVE_NODES:
        return jsonify({"success": False, "error": "node inconnu"}), 400

    vmid_int = validate_vmid(vmid)
    if vmid_int is None:
        return jsonify({"success": False, "error": "vmid invalide"}), 400

    ip = PVE_NODES[node]["ip"]
    name = PVE_NODES[node]["name"]

    try:
        r = requests.delete(
            f"https://{ip}:8006/api2/json/nodes/{name}/qemu/{vmid_int}",
            headers=HEADERS_PVE,
            verify=pve_verify_value(),
            timeout=10,
        )
        r.raise_for_status()
        logger.warning("Suppression VM: node=%s vmid=%s user=%s", node, vmid_int, session.get("user"))
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/vm/<node>/<vmid>/migrate", methods=["POST"])
@login_required
def api_vm_migrate(node, vmid):
    if node not in PVE_NODES:
        return jsonify({"success": False, "error": "node invalide"}), 400

    vmid_int = validate_vmid(vmid)
    if vmid_int is None:
        return jsonify({"success": False, "error": "vmid invalide"}), 400

    data = request.get_json(silent=True) or {}
    target = data.get("target")

    if not target or target not in PVE_NODES or target == node:
        return jsonify({"success": False, "error": "target invalide"}), 400

    ip = PVE_NODES[node]["ip"]
    source_node = PVE_NODES[node]["name"]

    try:
        r = requests.post(
            f"https://{ip}:8006/api2/json/nodes/{source_node}/qemu/{vmid_int}/migrate",
            headers=HEADERS_PVE,
            verify=pve_verify_value(),
            timeout=10,
            data={"target": target, "online": 1},
        )
        r.raise_for_status()
        logger.info("Migration VM: %s/%s -> %s user=%s", node, vmid_int, target, session.get("user"))
        return jsonify({"success": True, "message": f"Migration vers {target} lancée"})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


# -------------------------------------------------------------------
# SSH COMMANDS PROXMOX
# -------------------------------------------------------------------
PVE_SSH_USER = env_default("PVE_SSH_USER", "svc-proxmox")
ANSIBLE_HOST = env_default("ANSIBLE_HOST", "192.168.1.27")
ANSIBLE_SSH_USER = env_default("ANSIBLE_SSH_USER", "svc-ansible")


def run_ssh_command(host: str, user: str, command: str, timeout: int = 30) -> str:
    """
    Lance SSH sans shell local et avec BatchMode.
    Prévoir une clé SSH côté serveur Flask.
    """
    result = subprocess.check_output(
        [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=10",
            f"{user}@{host}",
            command,
        ],
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )
    return result


# -------------------------------------------------------------------
# LOGS PROXMOX
# -------------------------------------------------------------------
@app.route("/logs/<node>")
@login_required
def logs_node(node):
    ip = PVE_HOSTS.get(node)
    if not ip:
        return f"Node inconnu : {node}", 400

    cmd = "journalctl -n 50 --no-pager"

    try:
        out = run_ssh_command(ip, PVE_SSH_USER, cmd, timeout=30)
        return out
    except Exception as e:
        logger.warning("Erreur SSH logs %s: %s", node, e)
        return f"Erreur SSH : {e}", 500


# -------------------------------------------------------------------
# STORAGES
# -------------------------------------------------------------------
@app.route("/storages/<node>")
@login_required
def list_storages(node):
    ip = PVE_HOSTS.get(node)
    if not ip:
        return jsonify({"error": "node inconnu"}), 400

    try:
        cmd = f"pvesh get /nodes/{node}/storage --output-format json"
        out = run_ssh_command(ip, PVE_SSH_USER, cmd, timeout=30)
        return app.response_class(out, mimetype="application/json")
    except Exception as e:
        return jsonify({"error": str(e)})


# -------------------------------------------------------------------
# STATUS PANEL
# -------------------------------------------------------------------
def small_ping(host):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        result = subprocess.run(
            ["ping", param, "1", host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
        )
        return result.returncode == 0
    except Exception:
        return False


def check_ansible_host():
    return small_ping(ANSIBLE_HOST)


def check_terraform_host():
    return small_ping(env_default("TERRAFORM_HOST", "192.168.1.196"))


def check_jenkins():
    return small_ping(env_default("JENKINS_HOST", "192.168.1.132"))


def check_graylog():
    return small_ping(env_default("GRAYLOG_HOST", "192.168.1.48"))


def check_kubernetes():
    return small_ping(env_default("KUBERNETES_HOST", "192.168.1.4"))


@app.route("/status")
@login_required
def status():
    return jsonify({
        "terraform": check_terraform_host(),
        "ansible": check_ansible_host(),
        "jenkins": check_jenkins(),
        "graylog": check_graylog(),
        "kubernetes": check_kubernetes(),
        "pve-001": get_pve_stats("pve-001")["online"],
        "pve-002": get_pve_stats("pve-002")["online"],
        "pve-003": get_pve_stats("pve-003")["online"],
    })


# -------------------------------------------------------------------
# ANSIBLE AUTOMATION
# -------------------------------------------------------------------
@app.route("/ansible/run/<play>", methods=["POST"])
@login_required
def ansible_run_play(play):
    playbooks = {
        "ping": "/etc/ansible/ping.yml",
        "facts": "/etc/ansible/facts.yml",
    }

    if play not in playbooks:
        return jsonify({"success": False, "error": "Playbook inconnu"}), 400

    playbook_path = playbooks[play]
    cmd = f"ansible-playbook {playbook_path} -i /etc/ansible/inventory.ini"

    try:
        result = run_ssh_command(ANSIBLE_HOST, ANSIBLE_SSH_USER, cmd, timeout=300)
        logger.info("Ansible play=%s lancé par %s", play, session.get("user"))
        return jsonify({"success": True, "output": result})
    except subprocess.CalledProcessError as e:
        return jsonify({"success": False, "output": e.output})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


# -------------------------------------------------------------------
# DÉPLOIEMENT ANSIBLE DE SOLUTIONS
# -------------------------------------------------------------------
@app.route("/ansible/deploy", methods=["GET"])
@login_required
def ansible_deploy_menu():
    all_vms = []
    for node in PVE_NODES:
        for vm in list_vms(node):
            if vm.get("template"):
                continue
            vm["node"] = node
            all_vms.append(vm)

    return render_template("ansible_deploy.html", vms=all_vms, solutions=["Apache2"])


@app.route("/test")
@login_required
def test():
    return "OK"


@app.route("/vm_ip/<node>/<int:vmid>")
@login_required
def vm_ip(node, vmid):
    if node not in PVE_NODES:
        return jsonify({"error": "node inconnu"}), 400

    try:
        r = requests.get(
            f"https://{PVE_NODES[node]['ip']}:8006/api2/json/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces",
            headers=HEADERS_PVE,
            verify=pve_verify_value(),
            timeout=4,
        )

        raw = r.json()
        data = raw.get("data", {})

        if isinstance(data, str):
            data = json.loads(data)

        interfaces = data.get("result", [])

        for iface in interfaces:
            for ip_info in iface.get("ip-addresses", []):
                ip = ip_info.get("ip-address")
                ip_type = ip_info.get("ip-address-type")

                if ip and ip_type == "ipv4" and not ip.startswith("127."):
                    return jsonify({"ip": ip})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"ip": None})


@app.route("/ansible/run", methods=["POST"])
@login_required
def ansible_deploy_run():
    vmid = validate_vmid(request.form.get("vm"))
    target_ip = validate_ip(request.form.get("target_ip", ""))
    solution = request.form.get("solution")

    if vmid is None:
        return "<h3>❌ Erreur : VM invalide</h3>", 400

    if not target_ip:
        return "<h3>❌ Erreur : IP cible invalide</h3>", 400

    playbooks = {
        "Apache2": "/etc/ansible/playbooks/apache.yml",
    }

    if solution not in playbooks:
        return "<h3>❌ Erreur : solution inconnue</h3>", 400

    playbook = playbooks[solution]

    inventory_content = (
        "[web]\n"
        f"target ansible_host={target_ip} ansible_user={env_default('ANSIBLE_TARGET_USER', 'root')} "
        f"ansible_ssh_pass={env_default('ANSIBLE_TARGET_PASSWORD', '')}\n"
    )

    safe_inventory = json.dumps(inventory_content)

    ssh_inventory_cmd = (
        "python3 - <<'PY'\n"
        "from pathlib import Path\n"
        f"content = {safe_inventory}\n"
        "Path('/etc/ansible/inventory_webdeploy.ini').write_text(content)\n"
        "PY"
    )

    try:
        run_ssh_command(ANSIBLE_HOST, ANSIBLE_SSH_USER, ssh_inventory_cmd, timeout=30)

        cmd = f"ansible-playbook -i /etc/ansible/inventory_webdeploy.ini {playbook}"
        result = run_ssh_command(ANSIBLE_HOST, ANSIBLE_SSH_USER, cmd, timeout=600)

        logger.info("Déploiement Ansible solution=%s vmid=%s ip=%s user=%s", solution, vmid, target_ip, session.get("user"))
        return f"<pre>{result}</pre>"

    except subprocess.CalledProcessError as e:
        return f"<pre>❌ Erreur Ansible :\n{e.output}</pre>", 500

    except Exception as e:
        return f"<pre>❌ Erreur Python : {str(e)}</pre>", 500


# -------------------------------------------------------------------
# AUTHENTIFICATION LOGIN + 2FA
# -------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        username_ok = request.form.get("username") == ADMIN_USERNAME
        password_ok = bool(ADMIN_PASSWORD_HASH) and check_password_hash(
            ADMIN_PASSWORD_HASH,
            request.form.get("password", ""),
        )

        if username_ok and password_ok:
            session.clear()
            session["pre_2fa"] = True
            session.permanent = True
            logger.info("Login password OK pour %s depuis %s", ADMIN_USERNAME, request.remote_addr)
            return redirect("/2fa")

        logger.warning("Échec login depuis %s", request.remote_addr)
        flash("Identifiants invalides", "error")

    return render_template("login.html")


@app.route("/2fa", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def twofa():
    if "pre_2fa" not in session:
        return redirect("/login")

    if not TOTP_SECRET:
        flash("TOTP_SECRET non configuré côté serveur", "error")
        return render_template("2fa.html")

    totp = pyotp.TOTP(TOTP_SECRET)

    if request.method == "POST":
        if totp.verify(request.form.get("code", ""), valid_window=1):
            session["user"] = ADMIN_USERNAME
            session.pop("pre_2fa", None)
            logger.info("2FA OK pour %s depuis %s", ADMIN_USERNAME, request.remote_addr)
            return redirect("/")

        logger.warning("Échec 2FA depuis %s", request.remote_addr)
        flash("Code incorrect", "error")

    return render_template("2fa.html")


@app.route("/2fa_qr")
@login_required
def twofa_qr():
    if not TOTP_SECRET:
        return "TOTP_SECRET non configuré", 500

    totp = pyotp.TOTP(TOTP_SECRET)
    uri = totp.provisioning_uri(
        name=ADMIN_USERNAME,
        issuer_name="NebTech Dashboard",
    )

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    return send_file(
        buf,
        mimetype="image/png",
        as_attachment=False,
        download_name="2fa.png",
    )


@app.route("/logout")
def logout():
    logger.info("Logout user=%s", session.get("user"))
    session.clear()
    return redirect("/login")


# -------------------------------------------------------------------
# API GROUPES
# -------------------------------------------------------------------
@app.route("/groups", methods=["GET"])
@login_required
def get_groups():
    return jsonify({"groups": DEPLOYMENT_GROUPS})


@app.route("/groups/create", methods=["POST"])
@login_required
def create_group():
    global DEPLOYMENT_GROUPS

    data = request.get_json(silent=True) or {}
    name = validate_name(data.get("name"), max_len=48)
    modules = data.get("modules") or []

    if not name:
        return jsonify({"success": False, "error": "Nom de groupe manquant"}), 400
    if not modules or not isinstance(modules, list):
        return jsonify({"success": False, "error": "Aucun template sélectionné"}), 400

    valid_modules = [m for m in modules if m in TEMPLATES_INFO]
    if not valid_modules:
        return jsonify({"success": False, "error": "Templates invalides"}), 400

    DEPLOYMENT_GROUPS[name] = valid_modules
    save_groups(DEPLOYMENT_GROUPS)

    logger.info("Groupe créé/modifié: %s modules=%s user=%s", name, valid_modules, session.get("user"))
    return jsonify({"success": True})


# -------------------------------------------------------------------
# TERRAFORM ÉPHÉMÈRE
# -------------------------------------------------------------------
TERRAFORM_PROVIDER_VERSION = env_default("TERRAFORM_PROVIDER_VERSION", "0.87.0")
TERRAFORM_ENDPOINT = env_default("TERRAFORM_ENDPOINT", "https://192.168.1.122:8006")
TERRAFORM_PVE_USERNAME = env_default("TERRAFORM_PVE_USERNAME", "root@pam")
TERRAFORM_PVE_PASSWORD = os.getenv("TERRAFORM_PVE_PASSWORD", "")
TERRAFORM_DATASTORE = env_default("TERRAFORM_DATASTORE", "Shared-NFS")


def run_terraform(temp_dir: str) -> str:
    def run(cmd):
        process = subprocess.run(
            cmd,
            cwd=temp_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=1200,
        )
        return process.stdout

    output = "\n===== TERRAFORM INIT =====\n"
    output += run(["terraform", "init", "-upgrade"])

    output += "\n===== TERRAFORM APPLY =====\n"
    output += run(["terraform", "apply", "-auto-approve"])

    return output


def create_tf_project(vars_dict):
    temp_dir = tempfile.mkdtemp(prefix="tf-job-")

    try:
        main_tf = f"""
terraform {{
  required_providers {{
    proxmox = {{
      source  = "bpg/proxmox"
      version = "{TERRAFORM_PROVIDER_VERSION}"
    }}
  }}
}}

provider "proxmox" {{
  endpoint = "{TERRAFORM_ENDPOINT}"
  insecure = {str(not VERIFY_TLS).lower()}
  username = var.pve_username
  password = var.pve_password
}}

resource "proxmox_virtual_environment_vm" "vm" {{
  vm_id     = var.vm_id
  name      = var.vm_name
  node_name = var.node

  clone {{
    vm_id = var.template_id
    full = true
    datastore_id = var.datastore
  }}

  cpu {{
    cores = var.cpu
  }}

  memory {{
    dedicated = var.ram
  }}

  disk {{
    interface    = "scsi0"
    size         = var.disk
    datastore_id = var.datastore
  }}

  network_device {{
    bridge = var.bridge
  }}

  agent {{
    enabled = true
  }}
}}
"""

        variables_tf = """
variable "vm_id" {}
variable "vm_name" {}
variable "node" {}
variable "template_id" {}
variable "cpu" {}
variable "ram" {}
variable "disk" {}
variable "datastore" {}
variable "bridge" {}
variable "pve_username" { sensitive = true }
variable "pve_password" { sensitive = true }
"""

        vars_dict = {
            **vars_dict,
            "pve_username": TERRAFORM_PVE_USERNAME,
            "pve_password": TERRAFORM_PVE_PASSWORD,
        }

        allowed = {
            "vm_id", "vm_name", "node", "template_id",
            "cpu", "ram", "disk", "datastore", "bridge",
            "pve_username", "pve_password",
        }

        tfvars = ""
        for k, v in vars_dict.items():
            if k not in allowed:
                continue
            if isinstance(v, str):
                escaped = v.replace("\\", "\\\\").replace('"', '\\"')
                tfvars += f'{k} = "{escaped}"\n'
            else:
                tfvars += f"{k} = {v}\n"

        Path(temp_dir, "main.tf").write_text(main_tf, encoding="utf-8")
        Path(temp_dir, "variables.tf").write_text(variables_tf, encoding="utf-8")
        Path(temp_dir, "terraform.tfvars").write_text(tfvars, encoding="utf-8")

        output = run_terraform(temp_dir)
        logger.info("Terraform VM unique exécuté user=%s", session.get("user"))
        return output

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def create_tf_project_group(group_vm_list):
    temp_dir = tempfile.mkdtemp(prefix="tf-group-")

    try:
        terraform_block = f"""
terraform {{
  required_providers {{
    proxmox = {{
      source  = "bpg/proxmox"
      version = "{TERRAFORM_PROVIDER_VERSION}"
    }}
  }}
}}

variable "pve_username" {{ sensitive = true }}
variable "pve_password" {{ sensitive = true }}

provider "proxmox" {{
  endpoint = "{TERRAFORM_ENDPOINT}"
  insecure = {str(not VERIFY_TLS).lower()}
  username = var.pve_username
  password = var.pve_password
}}
"""

        resources = ""

        for i, vm in enumerate(group_vm_list):
            resources += f"""
resource "proxmox_virtual_environment_vm" "vm_{i}" {{
  vm_id     = {vm["vm_id"]}
  name      = "{vm["vm_name"]}"
  node_name = "{vm["node"]}"

  clone {{
    vm_id = {vm["template_id"]}
    full = true
    datastore_id = "{vm["datastore"]}"
  }}

  cpu {{
    cores = {vm["cpu"]}
  }}

  memory {{
    dedicated = {vm["ram"]}
  }}

  disk {{
    interface = "scsi0"
    size      = {vm["disk"]}
    datastore_id = "{vm["datastore"]}"
  }}

  network_device {{
    bridge = "{vm["bridge"]}"
  }}

  agent {{
    enabled = true
  }}
}}
"""

        main_tf = terraform_block + "\n" + resources

        tfvars = (
            f'pve_username = "{TERRAFORM_PVE_USERNAME.replace(chr(34), "")}"\n'
            f'pve_password = "{TERRAFORM_PVE_PASSWORD.replace(chr(34), "")}"\n'
        )

        Path(temp_dir, "main.tf").write_text(main_tf, encoding="utf-8")
        Path(temp_dir, "terraform.tfvars").write_text(tfvars, encoding="utf-8")

        output = run_terraform(temp_dir)
        logger.info("Terraform groupe exécuté count=%s user=%s", len(group_vm_list), session.get("user"))
        return output

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# -------------------------------------------------------------------
# DASHBOARD PRINCIPAL
# -------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    output = ""

    form = {
        "vm_name": "vm-demo",
        "vm_id": "200",
        "node": "pve-001",
        "template_id": "300",
        "cpu": "2",
        "ram": "4096",
        "disk": "30",
        "bridge": "vmbr0",
        "datastore": TERRAFORM_DATASTORE,
        "cloudinit_storage": TERRAFORM_DATASTORE,
        "sockets": "1",
    }

    if request.method == "POST":
        module = request.form.get("module", "")

        for k in form:
            form[k] = request.form.get(k, form[k])

        form["vm_name"] = validate_name(form["vm_name"])
        form["node"] = form["node"] if form["node"] in PVE_NODES else "pve-001"
        form["bridge"] = validate_name(form["bridge"], max_len=32)
        form["datastore"] = validate_name(form["datastore"], max_len=64)

        if module.startswith("group_"):
            group_name = module.replace("group_", "", 1)

            if group_name not in DEPLOYMENT_GROUPS:
                output = f"Groupe inconnu : {group_name}"
            else:
                template_keys = DEPLOYMENT_GROUPS[group_name]

                base_vm_id = safe_int(form["vm_id"], 200, 1, 999999999)
                base_name = form["vm_name"] or "groupvm"
                cpu = safe_int(form["cpu"], 2, 1, 64)
                ram = safe_int(form["ram"], 4096, 512, 524288)
                disk = safe_int(form["disk"], 30, 1, 4096)
                node = form["node"]
                bridge = form["bridge"]
                datastore = form["datastore"]

                group_vm_list = []
                current_id = base_vm_id

                for tpl_key in template_keys:
                    tpl = TEMPLATES_INFO.get(tpl_key)
                    if not tpl:
                        continue

                    group_vm_list.append({
                        "vm_id": current_id,
                        "vm_name": f"{base_name}-{current_id}",
                        "node": node,
                        "template_id": tpl["template_id"],
                        "cpu": cpu,
                        "ram": ram,
                        "disk": disk,
                        "bridge": bridge,
                        "datastore": datastore,
                    })

                    current_id += 1

                output = create_tf_project_group(group_vm_list)

        else:
            vars_dict = {
                "vm_id": safe_int(form["vm_id"], 200, 1, 999999999),
                "vm_name": form["vm_name"],
                "node": form["node"],
                "template_id": safe_int(form["template_id"], 300, 1, 999999999),
                "cpu": safe_int(form["cpu"], 2, 1, 64),
                "ram": safe_int(form["ram"], 4096, 512, 524288),
                "disk": safe_int(form["disk"], 30, 1, 4096),
                "bridge": form["bridge"],
                "datastore": form["datastore"],
            }

            output = create_tf_project(vars_dict)

    group_names = sorted(DEPLOYMENT_GROUPS.keys())

    return render_template(
        "index.html",
        form=form,
        output=output,
        deployment_groups=group_names,
        TEMPLATES_INFO=TEMPLATES_INFO,
        template_info=None,
    )


# -------------------------------------------------------------------
# ACCÈS CLI VM VIA SSH
# -------------------------------------------------------------------
CLI_SSH_USER = env_default("CLI_SSH_USER", "svc-vm")
CLI_SSH_PASSWORD = os.getenv("CLI_SSH_PASSWORD", "")


@app.route("/cli/vms")
@login_required
def cli_vms():
    all_vms = []

    for node in PVE_NODES:
        for vm in list_vms(node):
            if vm.get("template"):
                continue

            all_vms.append({
                "node": node,
                "vmid": vm.get("vmid"),
                "name": vm.get("name", f"VM-{vm.get('vmid')}"),
                "status": vm.get("status", "unknown"),
            })

    return jsonify(all_vms)


def get_vm_ipv4(node, vmid):
    if node not in PVE_NODES:
        return None

    vmid_int = validate_vmid(vmid)
    if vmid_int is None:
        return None

    r = requests.get(
        f"https://{PVE_NODES[node]['ip']}:8006/api2/json/nodes/{node}/qemu/{vmid_int}/agent/network-get-interfaces",
        headers=HEADERS_PVE,
        verify=pve_verify_value(),
        timeout=5,
    )

    raw = r.json()
    data = raw.get("data", {})

    if isinstance(data, str):
        data = json.loads(data)

    for iface in data.get("result", []):
        for ip_info in iface.get("ip-addresses", []):
            ip = ip_info.get("ip-address")
            ip_type = ip_info.get("ip-address-type")

            if ip and ip_type == "ipv4" and not ip.startswith("127."):
                return ip

    return None


@socketio.on("cli_connect")
def cli_connect(data):
    sid = request.sid

    if "user" not in session:
        emit("cli_output", "\r\n❌ Authentification requise.\r\n")
        return

    node = data.get("node")
    vmid = data.get("vmid")

    if node not in PVE_NODES or validate_vmid(vmid) is None:
        emit("cli_output", "\r\n❌ Node ou VMID invalide.\r\n")
        return

    try:
        ip = get_vm_ipv4(node, vmid)

        if not ip:
            emit(
                "cli_output",
                "\r\n❌ Impossible de récupérer l'adresse IP de la VM. Vérifie QEMU Guest Agent.\r\n",
            )
            return

        if not CLI_SSH_PASSWORD:
            emit("cli_output", "\r\n❌ CLI_SSH_PASSWORD non configuré côté serveur.\r\n")
            return

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.RejectPolicy())

        emit("cli_output", f"\r\nIP détectée : {ip}\r\n")
        emit("cli_output", f"Connexion SSH avec utilisateur : {CLI_SSH_USER}\r\n")

        ssh.connect(
            ip,
            username=CLI_SSH_USER,
            password=CLI_SSH_PASSWORD,
            timeout=10,
            look_for_keys=False,
            allow_agent=False,
            banner_timeout=10,
            auth_timeout=10,
        )

        channel = ssh.invoke_shell(term="xterm")

        SSH_SESSIONS[sid] = {"ssh": ssh, "channel": channel}

        logger.info("CLI connectée vmid=%s ip=%s user=%s", vmid, ip, session.get("user"))
        emit("cli_output", f"\r\n✅ Connecté à {ip}\r\n\r\n")

        def read_output():
            while sid in SSH_SESSIONS:
                ch = SSH_SESSIONS[sid]["channel"]

                if ch.recv_ready():
                    output = ch.recv(4096).decode(errors="ignore")
                    socketio.emit("cli_output", output, to=sid)

                socketio.sleep(0.02)

        socketio.start_background_task(read_output)

    except Exception as e:
        emit("cli_output", f"\r\n❌ Erreur CLI : {e}\r\n")


@socketio.on("cli_input")
def cli_input(data):
    sid = request.sid
    session_cli = SSH_SESSIONS.get(sid)

    if session_cli:
        session_cli["channel"].send(data)

@socketio.on("disconnect")
def cli_disconnect():
    sid = request.sid
    session_cli = SSH_SESSIONS.pop(sid, None)

    if session_cli:
        try:
            session_cli["channel"].close()
            session_cli["ssh"].close()
        except Exception:
            pass
# -------------------------------------------------------------------
# RUN
# -------------------------------------------------------------------
if __name__ == "__main__":
    ssl_cert = env_default("SSL_CERT", "dashboard.pem")
    ssl_key = env_default("SSL_KEY", "dashboard.key")
    port = env_int("APP_PORT", 443)

    if is_production():
        socketio.run(
            app,
            host="0.0.0.0",
            port=port,
            ssl_context=(ssl_cert, ssl_key),
            debug=False,
            allow_unsafe_werkzeug=False,
        )
    else:
        socketio.run(app, host="0.0.0.0", port=port, debug=True)
