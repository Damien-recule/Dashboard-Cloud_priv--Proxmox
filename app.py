#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NebTech Cloud Dashboard
Auteur : Damien RECULE
Date : 01/12/2025
Version : 3.1

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
# Ajout de la ligne qui suit 24.01.2026
from OpenSSL import SSL, crypto
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    flash,
    jsonify,
)
import subprocess
import os
import secrets
import pyotp
import platform
import time
import requests
import json
import urllib3
import tempfile
import shutil

urllib3.disable_warnings()

# -------------------------------------------------------------------
# FLASK APP
# -------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# -------------------------------------------------------------------
# CONFIG PROXMOX
# -------------------------------------------------------------------
PVE_NODES = {
    "pve01": {"ip": "192.168.1.193", "name": "pve01"},
    "pve02": {"ip": "192.168.1.194", "name": "pve02"},
    "pve03": {"ip": "192.168.1.195", "name": "pve03"},
}

PVE_HOSTS = {
    "pve01": "192.168.1.193",
    "pve02": "192.168.1.194",
    "pve03": "192.168.1.195",
}

PVE_TOKEN_ID = "root@pam!dashboard"
PVE_SECRET = "fb6b2feb-ff3e-4bc3-8a3a-f40ae7ef2e63"

HEADERS_PVE = {
    "Authorization": f"PVEAPIToken={PVE_TOKEN_ID}={PVE_SECRET}"
}

# -------------------------------------------------------------------
# TEMPLATES Proxmox (ID → description)
# -------------------------------------------------------------------
TEMPLATES_INFO = {
    "tpl_300": {"template_id": 300, "name": "Debian 12 Base"},
    "tpl_301": {"template_id": 301, "name": "Bastion SSH"},
    "tpl_302": {"template_id": 302, "name": "HAProxy"},
    "tpl_303": {"template_id": 303, "name": "Prometheus"},
    "tpl_304": {"template_id": 304, "name": "Grafana"},
    "tpl_305": {"template_id": 305, "name": "Node Exporter"},
    "tpl_306": {"template_id": 306, "name": "Ansible"},
    "tpl_307": {"template_id": 307, "name": "K8s Master"},
    "tpl_308": {"template_id": 308, "name": "K8s Worker"},
    "tpl_309": {"template_id": 309, "name": "Registry"},
    "tpl_310": {"template_id": 310, "name": "Crowdsec"},
    "tpl_311": {"template_id": 311, "name": "Loki"},
    "tpl_312": {"template_id": 312, "name": "Infra Prometheus"},
    "tpl_313": {"template_id": 313, "name": "Infra NodeExporter"},
    "tpl_314": {"template_id": 314, "name": "Redis"},
    "tpl_315": {"template_id": 315, "name": "PostgreSQL"},
    "tpl_316": {"template_id": 316, "name": "Keycloak"},
    "tpl_317": {"template_id": 317, "name": "OpenVAS"},
    "tpl_318": {"template_id": 318, "name": "pfSense"},
    "tpl_319": {"template_id": 319, "name": "Windows 2022"},
    "tpl_320": {"template_id": 320, "name": "Ubuntu Minimal"},
    "tpl_321": {"template_id": 321, "name": "Windows 11"},
    "tpl_322": {"template_id": 322, "name": "Terraform"},
    "tpl_323": {"template_id": 323, "name": "Jenkins"},
    "tpl_324": {"template_id": 324, "name": "Debian-deploy"},
}
# Ajout 24.01.2026

#@app.before_request
#def check_client_cert():
#    """
#    Vérifie si le client présente un certificat.
#    Si non → affiche page personnalisée.
#    """
#    # SSL_CLIENT_CERT doit être fourni par ton serveur (Nginx / WSGI) ou via ssl_context custom
#    cert_pem = request.environ.get('SSL_CLIENT_CERT')
#
#    if not cert_pem:
#        # Pas de certificat → refuser l'accès
#        return render_template("no_cert.html"), 403
#
#    try:
#        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
#        request.client_cn = x509.get_subject().CN  # On peut récupérer le CN pour l'utiliser
#    except Exception:
#        return render_template("no_cert.html"), 403


# -------------------------------------------------------------------
# GROUPES DE DÉPLOIEMENT
# -------------------------------------------------------------------
GROUPS_FILE = "/etc/terraform/cloud-project/environments/production/groups.json"

DEFAULT_GROUPS = {
    "LAB-SIEM": [
        "tpl_319",  # Windows 2022
        "tpl_315",  # PostgreSQL
    ],
    "Cluster-Dev": [
        "tpl_300",  # Debian base
        "tpl_304",  # Grafana
        "tpl_303",  # Prometheus
    ],
}


def load_groups():
    if os.path.exists(GROUPS_FILE):
        try:
            with open(GROUPS_FILE, "r") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception as e:
            print("Erreur lecture groups.json:", e)
    return DEFAULT_GROUPS.copy()


def save_groups(groups):
    try:
        with open(GROUPS_FILE, "w") as f:
            json.dump(groups, f, indent=2)
    except Exception as e:
        print("Erreur sauvegarde groupes:", e)


DEPLOYMENT_GROUPS = load_groups()

# -------------------------------------------------------------------
# PING & Monitoring Proxmox
# -------------------------------------------------------------------
def ping_ms(ip: str):
    try:
        start = time.time()
        out = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if out.returncode == 0:
            return round((time.time() - start) * 1000, 1)
    except Exception:
        pass
    return None


def get_pve_stats(node):
    if node not in PVE_NODES:
        return {"online": False}

    ip = PVE_NODES[node]["ip"]
    name = PVE_NODES[node]["name"]

    latency = ping_ms(ip)
    if latency is None:
        return {"online": False, "ping": None}

    try:
        r = requests.get(
            f"https://{ip}:8006/api2/json/nodes/{name}/status",
            headers=HEADERS_PVE,
            verify=False,
            timeout=4,
        )
        r.raise_for_status()
        data = r.json()["data"]

        cpu = round(data["cpu"] * 100, 1)
        ram = round(data["memory"]["used"] / data["memory"]["total"] * 100, 1)
        disk = round(data["rootfs"]["used"] / data["rootfs"]["total"] * 100, 1)

        r2 = requests.get(
            f"https://{ip}:8006/api2/json/nodes/{name}/qemu",
            headers=HEADERS_PVE,
            verify=False,
            timeout=3,
        )
        r2.raise_for_status()
        vms = r2.json()["data"]

    except Exception:
        return {"online": True, "ping": latency}

    return {
        "online": True,
        "ping": latency,
        "cpu": cpu,
        "ram": ram,
        "disk": disk,
        "vm": len(vms),
    }


@app.route("/monitor/<node>")
def api_monitor(node):
    return jsonify(get_pve_stats(node))

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
            verify=False,
            timeout=4,
        )
        r.raise_for_status()
        return r.json()["data"]
    except Exception as e:
        print("Erreur list_vms:", e)
        return []


def vm_action(node, vmid, action):
    if node not in PVE_NODES:
        return {"success": False, "error": "node inconnu"}

    ip = PVE_NODES[node]["ip"]
    name = PVE_NODES[node]["name"]

    try:
        r = requests.post(
            f"https://{ip}:8006/api2/json/nodes/{name}/qemu/{vmid}/status/{action}",
            headers=HEADERS_PVE,
            verify=False,
            timeout=4,
        )
        r.raise_for_status()
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.route("/vms/<node>")
def api_list_vms(node):
    if node not in PVE_NODES:
        return jsonify({"error": "node inconnu"}), 400
    return jsonify(list_vms(node))


@app.route("/vm/<node>/<vmid>/<action>", methods=["POST"])
def api_vm(node, vmid, action):
    if action not in ["start", "stop", "reset"]:
        return jsonify({"error": "action invalide"}), 400
    return jsonify(vm_action(node, vmid, action))


@app.route("/vm/<node>/<vmid>/delete", methods=["POST"])
def api_vm_delete(node, vmid):
    if node not in PVE_NODES:
        return jsonify({"success": False, "error": "node inconnu"}), 400

    ip = PVE_NODES[node]["ip"]
    name = PVE_NODES[node]["name"]

    try:
        r = requests.delete(
            f"https://{ip}:8006/api2/json/nodes/{name}/qemu/{vmid}",
            headers=HEADERS_PVE,
            verify=False,
            timeout=10,
        )
        r.raise_for_status()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/vm/<node>/<vmid>/migrate", methods=["POST"])
def migrate_vm(node, vmid):
    data = request.get_json()
    target = data.get("target")

    if target not in PVE_NODES:
        return jsonify({"message": "Nœud cible invalide"}), 400

    source_ip = PVE_NODES[node]["ip"]

    try:
        # 1️⃣ Arrêt VM
        subprocess.run(
            ["ssh", f"root@{source_ip}", f"qm stop {vmid}"],
            check=True
        )

        # 2️⃣ Migration à froid
        subprocess.run(
            ["ssh", f"root@{source_ip}", f"qm migrate {vmid} {target}"],
            check=True
        )

        return jsonify({
            "message": f"✅ VM {vmid} migrée vers {target} avec succès"
        })

    except subprocess.CalledProcessError as e:
        return jsonify({
            "message": f"❌ Erreur migration : {str(e)}"
        }), 500


# -------------------------------------------------------------------
# LOGS PROXMOX
# -------------------------------------------------------------------
@app.route("/logs/<node>")
def logs_node(node):
    ip = PVE_HOSTS.get(node)
    if not ip:
        return f"Node inconnu : {node}", 400

    cmd = "journalctl -n 50 --no-pager"

    try:
        out = subprocess.check_output(
            ["ssh", f"root@{ip}", cmd],
            text=True,
        )
        return out
    except Exception as e:
        return f"Erreur SSH : {e}", 500

# -------------------------------------------------------------------
# STORAGES
# -------------------------------------------------------------------
@app.route("/storages/<node>")
def list_storages(node):
    ip = PVE_HOSTS.get(node)
    if not ip:
        return jsonify({"error": "node inconnu"}), 400

    try:
        cmd = f"pvesh get /nodes/{node}/storage --output-format json"
        out = subprocess.check_output(["ssh", f"root@{ip}", cmd], text=True)
        return out
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
        )
        return result.returncode == 0
    except Exception:
        return False


def check_jenkins():
    return small_ping("192.168.1.62")


def check_ansible_host():
    return small_ping("192.168.1.134")


def check_graylog():
    return small_ping("192.168.1.172")


def check_docker():
    return small_ping("192.168.1.172")


def check_terraform_host():
    return small_ping("192.168.1.12")


def check_pve1():
    return small_ping("192.168.1.193")


def check_pve2():
    return small_ping("192.168.1.194")


def check_pve3():
    return small_ping("192.168.1.195")


@app.route("/status")
def status():
    return jsonify(
        {
            "jenkins": check_jenkins(),
            "ansible": check_ansible_host(),
            "terraform": check_terraform_host(),
            "graylog": check_graylog(),
            "docker": check_docker(),
            "pve1": check_pve1(),
            "pve2": check_pve2(),
            "pve3": check_pve3(),
        }
    )

# -------------------------------------------------------------------
# ANSIBLE AUTOMATION (PING / MAJ – EXISTANT)
# -------------------------------------------------------------------
@app.route("/ansible/run/<play>", methods=["POST"])
def ansible_run_play(play):
    """
    Utilisé par les boutons "Test ping Ansible" et "Mise à jour Ansible"
    dans le dashboard (JS → /ansible/run/ping ou /ansible/run/maj).
    """

    playbooks = {
        "ping": "/etc/ansible/ping.yml",
        "maj": "/etc/ansible/maj.yml",
    }

    if play not in playbooks:
        return jsonify({"success": False, "error": "Playbook inconnu"}), 400

    playbook_path = playbooks[play]

    try:
        result = subprocess.check_output(
            [
                "ssh",
                "root@192.168.1.134",
                f"ansible-playbook {playbook_path} -i /etc/ansible/inventory.ini",
            ],
            stderr=subprocess.STDOUT,
            text=True,
            timeout=300,
        )
        return jsonify({"success": True, "output": result})
    except subprocess.CalledProcessError as e:
        return jsonify({"success": False, "output": e.output})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# -------------------------------------------------------------------
# DÉPLOIEMENT ANSIBLE DE SOLUTIONS (Apache2, etc.)
# -------------------------------------------------------------------

@app.route("/ansible/deploy", methods=["GET"])
def ansible_deploy_menu():
    all_vms = []
    for node in PVE_NODES:
        for vm in list_vms(node):
            if vm.get("template"):
                continue
            vm["node"] = node
            all_vms.append(vm)

    return render_template(
        "ansible_deploy.html",
        vms=all_vms,
        solutions = [
            "Bootstrap",
            "Bind9",
            "Nginx",
            "Zabbix",
            "Graylog",
            "GLPI"
        ]

    )



# -------------------------------------------------------------------
# ANSIBLE : LANCEMENT DU DÉPLOIEMENT APACHE2
# -------------------------------------------------------------------

@app.route("/vm_ip/<node>/<int:vmid>")
def vm_ip(node, vmid):
    """
    Renvoie l'adresse IP détectée via QEMU Guest Agent.
    """
    try:
        r = requests.get(
            f"https://{PVE_NODES[node]['ip']}:8006/api2/json/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces",
            headers=HEADERS_PVE,
            verify=False,
            timeout=4
        )
        data = r.json().get("data", {})
        interfaces = data.get("result", [])

        for iface in interfaces:
            if "ip-addresses" in iface:
                for ip_info in iface["ip-addresses"]:
                    if ip_info.get("ip-address") and ip_info.get("ip-address-type") == "ipv4":
                        ip = ip_info["ip-address"]
                        if not ip.startswith("127"):
                            return jsonify({"ip": ip})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"ip": None})


@app.route("/ansible/run", methods=["POST"])
def ansible_deploy_run():
    target_ip = request.form.get("target_ip")
    solution = request.form.get("solution")

    if not target_ip or not solution:
        return "Erreur paramètres", 400

    inventory_path = "/etc/ansible/playbooks/inventory_webdeploy.ini"

    # 1️⃣ Génération de l'inventaire (sur le serveur Ansible)
    inventory_content = (
        "[target]\n"
        f"vm1 ansible_host={target_ip} ansible_user=root ansible_ssh_pass=1234\n"
    )

    subprocess.run(
        [
            "ssh",
            "root@192.168.1.134",
            f"echo '{inventory_content}' > {inventory_path}"
        ],
        text=True
    )

    playbooks = {
        "Bootstrap": "bootstrap.yml",
        "Bind9": "bind9.yml",
        "Nginx": "nginx.yml",
        "Zabbix": "zabbix.yml",
        "Graylog": "graylog.yml",
        "GLPI": "glpi.yml",
    }

    if solution not in playbooks:
        return "Solution inconnue", 400

    playbook = playbooks[solution]

    # 2️⃣ Lancer Ansible avec l'inventaire dédié
    result = subprocess.run(
        [
            "ssh",
            "root@192.168.1.134",
            "ansible-playbook",
            f"/etc/ansible/playbooks/{playbook}",
            "-i",
            inventory_path,
        ],
        capture_output=True,
        text=True,
    )

    return (
        "<pre>"
        + result.stdout
        + "\n"
        + result.stderr
        + "</pre>"
    )


# -------------------------------------------------------------------
# AUTHENTIFICATION (LOGIN + 2FA)
# -------------------------------------------------------------------
ADMIN_USERNAME = "nebtech_admin_231177"
ADMIN_PASSWORD = "Nbtawyhtp@@1977"
TOTP_SECRET = pyotp.random_base32()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if (
            request.form.get("username") == ADMIN_USERNAME
            and request.form.get("password") == ADMIN_PASSWORD
        ):
            session["pre_2fa"] = True
            return redirect("/2fa")

        flash("Identifiants invalides", "error")

    return render_template("login.html")


@app.route("/2fa", methods=["GET", "POST"])
def twofa():
    if "pre_2fa" not in session:
        return redirect("/login")

    totp = pyotp.TOTP(TOTP_SECRET)

    if request.method == "POST":
        if totp.verify(request.form.get("code")):
            session["user"] = ADMIN_USERNAME
            session.pop("pre_2fa", None)
            return redirect("/")
        flash("Code incorrect", "error")

    return render_template("2fa.html")


@app.route("/2fa_qr")
def twofa_qr():
    totp = pyotp.TOTP(TOTP_SECRET)
    uri = totp.provisioning_uri(
        name="NebTech_Admin", issuer_name="NebTech Dashboard"
    )

    import qrcode
    import io
    from flask import send_file

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# -------------------------------------------------------------------
# API GROUPES
# -------------------------------------------------------------------
@app.route("/groups", methods=["GET"])
def get_groups():
    return jsonify({"groups": DEPLOYMENT_GROUPS})


@app.route("/groups/create", methods=["POST"])
def create_group():
    global DEPLOYMENT_GROUPS

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    modules = data.get("modules") or []

    if not name:
        return jsonify({"success": False, "error": "Nom de groupe manquant"}), 400
    if not modules:
        return jsonify({"success": False, "error": "Aucun template sélectionné"}), 400

    valid_modules = [m for m in modules if m in TEMPLATES_INFO]
    if not valid_modules:
        return jsonify({"success": False, "error": "Templates invalides"}), 400

    DEPLOYMENT_GROUPS[name] = valid_modules
    save_groups(DEPLOYMENT_GROUPS)

    return jsonify({"success": True})

# -------------------------------------------------------------------
# TERRAFORM ÉPHÉMÈRE (1 VM)
# -------------------------------------------------------------------
def create_tf_project(vars_dict):
    temp_dir = tempfile.mkdtemp(prefix="tf-job-")

    main_tf = """
    terraform {
      required_providers {
        proxmox = {
          source  = "bpg/proxmox"
          version = "0.87.0"
        }
      }
    }

    module "vm" {
      source = "/etc/terraform/cloud-project/modules/vm_generic"

      vm_id             = var.vm_id
      vm_name           = var.vm_name
      node              = var.node
      template_id       = var.template_id
      cpu               = var.cpu
      sockets           = var.sockets
      ram               = var.ram
      disk              = var.disk
      datastore         = var.datastore
      bridge            = var.bridge
      cloudinit_storage = var.cloudinit_storage
    }
    """

    provider_tf = """
    provider "proxmox" {
      endpoint = "https://192.168.1.193:8006/"
      insecure = true
      username = "root@pam"
      password = "Nbtawyhtp@@1977"
    }
    """

    variables_tf = """
    variable "vm_id" {}
    variable "vm_name" {}
    variable "node" {}
    variable "template_id" {}
    variable "cpu" {}
    variable "sockets" {}
    variable "ram" {}
    variable "disk" {}
    variable "datastore" {}
    variable "bridge" {}
    variable "cloudinit_storage" {}
    """

    tfvars = ""
    for k, v in vars_dict.items():
        if isinstance(v, str):
            tfvars += f'{k} = "{v}"\n'
        else:
            tfvars += f"{k} = {v}\n"

    open(os.path.join(temp_dir, "main.tf"), "w").write(main_tf)
    open(os.path.join(temp_dir, "provider.tf"), "w").write(provider_tf)
    open(os.path.join(temp_dir, "variables.tf"), "w").write(variables_tf)
    open(os.path.join(temp_dir, "terraform.tfvars"), "w").write(tfvars)

    def run(cmd):
        process = subprocess.run(
            cmd,
            cwd=temp_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        return process.stdout

    output = "\n===== TERRAFORM INIT =====\n"
    output += run(["terraform", "init", "-upgrade"])

    output += "\n===== TERRAFORM APPLY =====\n"
    output += run(["terraform", "apply", "-auto-approve"])

    shutil.rmtree(temp_dir, ignore_errors=True)

    return output

# -------------------------------------------------------------------
# TERRAFORM ÉPHÉMÈRE (GROUPE MULTI-VM)
# -------------------------------------------------------------------
def create_tf_project_group(group_vm_list):
    temp_dir = tempfile.mkdtemp(prefix="tf-group-")

    terraform_block = """
terraform {
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "0.87.0"
    }
  }
}

provider "proxmox" {
  endpoint = "https://192.168.1.193:8006/"
  insecure = true
  username = "root@pam"
  password = "Nbtawyhtp@@1977"
}
"""

    modules_block = ""

    for idx, vm in enumerate(group_vm_list, start=1):
        modules_block += f"""
module "vm_{idx}" {{
  source = "/etc/terraform/cloud-project/modules/vm_generic"

  vm_id             = {vm["vm_id"]}
  vm_name           = "{vm["vm_name"]}"
  node              = "{vm["node"]}"
  template_id       = {vm["template_id"]}
  cpu               = {vm["cpu"]}
  sockets           = {vm["sockets"]}
  ram               = {vm["ram"]}
  disk              = {vm["disk"]}
  datastore         = "{vm["datastore"]}"
  bridge            = "{vm["bridge"]}"
  cloudinit_storage = "{vm["cloudinit_storage"]}"
}}
"""

    main_tf_content = terraform_block + "\n" + modules_block
    with open(os.path.join(temp_dir, "main.tf"), "w") as f:
        f.write(main_tf_content)

    def run(cmd):
        process = subprocess.run(
            cmd,
            cwd=temp_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        return process.stdout

    output = "\n===== TERRAFORM INIT (GROUPE) =====\n"
    output += run(["terraform", "init", "-upgrade"])

    output += "\n===== TERRAFORM APPLY (GROUPE) =====\n"
    output += run(["terraform", "apply", "-auto-approve"])

    shutil.rmtree(temp_dir, ignore_errors=True)

    return output

# -------------------------------------------------------------------
# DASHBOARD PRINCIPAL
# -------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    if "user" not in session:
        return redirect("/login")

    output = ""

    form = {
        "vm_name": "vm-demo",
        "vm_id": "200",
        "node": "pve01",
        "template_id": "300",
        "cpu": "2",
        "ram": "4096",
        "disk": "30",
        "bridge": "vmbr0",
        "datastore": "vmstore",
        "cloudinit_storage": "vmstore",
        "sockets": "1",
    }

    if request.method == "POST":
        module = request.form.get("module", "")

        for k in form:
            form[k] = request.form.get(k, form[k])

        # CAS 2 : GROUPE
        if module.startswith("group_"):
            group_name = module.replace("group_", "", 1)

            if group_name not in DEPLOYMENT_GROUPS:
                output = f"Groupe inconnu : {group_name}"
            else:
                template_keys = DEPLOYMENT_GROUPS[group_name]

                try:
                    base_vm_id = int(form["vm_id"])
                    base_name = form["vm_name"] or "groupvm"
                    cpu = int(form["cpu"])
                    ram = int(form["ram"])
                    disk = int(form["disk"])
                    sockets = int(form["sockets"])
                    node = form["node"]
                    bridge = form["bridge"]
                    datastore = form["datastore"]
                    cloudinit = form["cloudinit_storage"]
                except (ValueError, TypeError) as e:
                    output = f"Erreur valeurs groupe : {e}"
                else:
                    group_vm_list = []
                    current_id = base_vm_id

                    for tpl_key in template_keys:
                        tpl = TEMPLATES_INFO.get(tpl_key)
                        if not tpl:
                            continue

                        group_vm_list.append(
                            {
                                "vm_id": current_id,
                                "vm_name": f"{base_name}-{current_id}",
                                "node": node,
                                "template_id": tpl["template_id"],
                                "cpu": cpu,
                                "ram": ram,
                                "disk": disk,
                                "bridge": bridge,
                                "datastore": datastore,
                                "cloudinit_storage": cloudinit,
                                "sockets": sockets,
                            }
                        )

                        current_id += 1

                    output = create_tf_project_group(group_vm_list)

        # CAS 1 : VM UNIQUE
        else:
            if module not in TEMPLATES_INFO:
                output = f"Template inconnu : {module}"
            else:
                tpl = TEMPLATES_INFO[module]

                try:
                    vars_dict = {
                        "vm_id": int(form["vm_id"]),
                        "vm_name": form["vm_name"],
                        "node": form["node"],
                        "template_id": tpl["template_id"],
                        "cpu": int(form["cpu"]),
                        "ram": int(form["ram"]),
                        "disk": int(form["disk"]),
                        "bridge": form["bridge"],
                        "datastore": form["datastore"],
                        "cloudinit_storage": form["cloudinit_storage"],
                        "sockets": int(form["sockets"]),
                    }
                except (ValueError, TypeError) as e:
                    output = (
                        "Erreur dans les valeurs du formulaire "
                        f"(conversion en entier) : {e}"
                    )
                else:
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
# RUN
# -------------------------------------------------------------------
#if __name__ == "__main__":
#    app.run(host="0.0.0.0", port=443, ssl_context=("dashboard.pem", "dashboard.key"))

# MODIFICATION 24.01.2026
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=443,
        ssl_context=("dashboard.pem", "dashboard.key"),
        debug=True
    )
root@debian:~/cloud-dashboard/app#
root@debian:~/cloud-dashboard/app# cat app.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NebTech Cloud Dashboard
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
# Ajout de la ligne qui suit 24.01.2026
from OpenSSL import SSL, crypto
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    flash,
    jsonify,
)
import subprocess
import os
import secrets
import pyotp
import platform
import time
import requests
import json
import urllib3
import tempfile
import shutil

urllib3.disable_warnings()

# -------------------------------------------------------------------
# FLASK APP
# -------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# -------------------------------------------------------------------
# CONFIG PROXMOX
# -------------------------------------------------------------------
PVE_NODES = {
    "pve01": {"ip": "192.168.1.193", "name": "pve01"},
    "pve02": {"ip": "192.168.1.194", "name": "pve02"},
    "pve03": {"ip": "192.168.1.195", "name": "pve03"},
}

PVE_HOSTS = {
    "pve01": "192.168.1.193",
    "pve02": "192.168.1.194",
    "pve03": "192.168.1.195",
}

PVE_TOKEN_ID = "root@pam!dashboard"
PVE_SECRET = "fb6b2feb-ff3e-4bc3-8a3a-f40ae7ef2e63"

HEADERS_PVE = {
    "Authorization": f"PVEAPIToken={PVE_TOKEN_ID}={PVE_SECRET}"
}

# -------------------------------------------------------------------
# TEMPLATES Proxmox (ID → description)
# -------------------------------------------------------------------
TEMPLATES_INFO = {
    "tpl_300": {"template_id": 300, "name": "Debian 12 Base"},
    "tpl_301": {"template_id": 301, "name": "Bastion SSH"},
    "tpl_302": {"template_id": 302, "name": "HAProxy"},
    "tpl_303": {"template_id": 303, "name": "Prometheus"},
    "tpl_304": {"template_id": 304, "name": "Grafana"},
    "tpl_305": {"template_id": 305, "name": "Node Exporter"},
    "tpl_306": {"template_id": 306, "name": "Ansible"},
    "tpl_307": {"template_id": 307, "name": "K8s Master"},
    "tpl_308": {"template_id": 308, "name": "K8s Worker"},
    "tpl_309": {"template_id": 309, "name": "Registry"},
    "tpl_310": {"template_id": 310, "name": "Crowdsec"},
    "tpl_311": {"template_id": 311, "name": "Loki"},
    "tpl_312": {"template_id": 312, "name": "Infra Prometheus"},
    "tpl_313": {"template_id": 313, "name": "Infra NodeExporter"},
    "tpl_314": {"template_id": 314, "name": "Redis"},
    "tpl_315": {"template_id": 315, "name": "PostgreSQL"},
    "tpl_316": {"template_id": 316, "name": "Keycloak"},
    "tpl_317": {"template_id": 317, "name": "OpenVAS"},
    "tpl_318": {"template_id": 318, "name": "pfSense"},
    "tpl_319": {"template_id": 319, "name": "Windows 2022"},
    "tpl_320": {"template_id": 320, "name": "Ubuntu Minimal"},
    "tpl_321": {"template_id": 321, "name": "Windows 11"},
    "tpl_322": {"template_id": 322, "name": "Terraform"},
    "tpl_323": {"template_id": 323, "name": "Jenkins"},
    "tpl_324": {"template_id": 324, "name": "Debian-deploy"},
}
# Ajout 24.01.2026

#@app.before_request
#def check_client_cert():
#    """
#    Vérifie si le client présente un certificat.
#    Si non → affiche page personnalisée.
#    """
#    # SSL_CLIENT_CERT doit être fourni par ton serveur (Nginx / WSGI) ou via ssl_context custom
#    cert_pem = request.environ.get('SSL_CLIENT_CERT')
#
#    if not cert_pem:
#        # Pas de certificat → refuser l'accès
#        return render_template("no_cert.html"), 403
#
#    try:
#        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
#        request.client_cn = x509.get_subject().CN  # On peut récupérer le CN pour l'utiliser
#    except Exception:
#        return render_template("no_cert.html"), 403


# -------------------------------------------------------------------
# GROUPES DE DÉPLOIEMENT
# -------------------------------------------------------------------
GROUPS_FILE = "/etc/terraform/cloud-project/environments/production/groups.json"

DEFAULT_GROUPS = {
    "LAB-SIEM": [
        "tpl_319",  # Windows 2022
        "tpl_315",  # PostgreSQL
    ],
    "Cluster-Dev": [
        "tpl_300",  # Debian base
        "tpl_304",  # Grafana
        "tpl_303",  # Prometheus
    ],
}


def load_groups():
    if os.path.exists(GROUPS_FILE):
        try:
            with open(GROUPS_FILE, "r") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception as e:
            print("Erreur lecture groups.json:", e)
    return DEFAULT_GROUPS.copy()


def save_groups(groups):
    try:
        with open(GROUPS_FILE, "w") as f:
            json.dump(groups, f, indent=2)
    except Exception as e:
        print("Erreur sauvegarde groupes:", e)


DEPLOYMENT_GROUPS = load_groups()

# -------------------------------------------------------------------
# PING & Monitoring Proxmox
# -------------------------------------------------------------------
def ping_ms(ip: str):
    try:
        start = time.time()
        out = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if out.returncode == 0:
            return round((time.time() - start) * 1000, 1)
    except Exception:
        pass
    return None


def get_pve_stats(node):
    if node not in PVE_NODES:
        return {"online": False}

    ip = PVE_NODES[node]["ip"]
    name = PVE_NODES[node]["name"]

    latency = ping_ms(ip)
    if latency is None:
        return {"online": False, "ping": None}

    try:
        r = requests.get(
            f"https://{ip}:8006/api2/json/nodes/{name}/status",
            headers=HEADERS_PVE,
            verify=False,
            timeout=4,
        )
        r.raise_for_status()
        data = r.json()["data"]

        cpu = round(data["cpu"] * 100, 1)
        ram = round(data["memory"]["used"] / data["memory"]["total"] * 100, 1)
        disk = round(data["rootfs"]["used"] / data["rootfs"]["total"] * 100, 1)

        r2 = requests.get(
            f"https://{ip}:8006/api2/json/nodes/{name}/qemu",
            headers=HEADERS_PVE,
            verify=False,
            timeout=3,
        )
        r2.raise_for_status()
        vms = r2.json()["data"]

    except Exception:
        return {"online": True, "ping": latency}

    return {
        "online": True,
        "ping": latency,
        "cpu": cpu,
        "ram": ram,
        "disk": disk,
        "vm": len(vms),
    }


@app.route("/monitor/<node>")
def api_monitor(node):
    return jsonify(get_pve_stats(node))

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
            verify=False,
            timeout=4,
        )
        r.raise_for_status()
        return r.json()["data"]
    except Exception as e:
        print("Erreur list_vms:", e)
        return []


def vm_action(node, vmid, action):
    if node not in PVE_NODES:
        return {"success": False, "error": "node inconnu"}

    ip = PVE_NODES[node]["ip"]
    name = PVE_NODES[node]["name"]

    try:
        r = requests.post(
            f"https://{ip}:8006/api2/json/nodes/{name}/qemu/{vmid}/status/{action}",
            headers=HEADERS_PVE,
            verify=False,
            timeout=4,
        )
        r.raise_for_status()
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.route("/vms/<node>")
def api_list_vms(node):
    if node not in PVE_NODES:
        return jsonify({"error": "node inconnu"}), 400
    return jsonify(list_vms(node))


@app.route("/vm/<node>/<vmid>/<action>", methods=["POST"])
def api_vm(node, vmid, action):
    if action not in ["start", "stop", "reset"]:
        return jsonify({"error": "action invalide"}), 400
    return jsonify(vm_action(node, vmid, action))


@app.route("/vm/<node>/<vmid>/delete", methods=["POST"])
def api_vm_delete(node, vmid):
    if node not in PVE_NODES:
        return jsonify({"success": False, "error": "node inconnu"}), 400

    ip = PVE_NODES[node]["ip"]
    name = PVE_NODES[node]["name"]

    try:
        r = requests.delete(
            f"https://{ip}:8006/api2/json/nodes/{name}/qemu/{vmid}",
            headers=HEADERS_PVE,
            verify=False,
            timeout=10,
        )
        r.raise_for_status()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/vm/<node>/<vmid>/migrate", methods=["POST"])
def migrate_vm(node, vmid):
    data = request.get_json()
    target = data.get("target")

    if target not in PVE_NODES:
        return jsonify({"message": "Nœud cible invalide"}), 400

    source_ip = PVE_NODES[node]["ip"]

    try:
        # 1️⃣ Arrêt VM
        subprocess.run(
            ["ssh", f"root@{source_ip}", f"qm stop {vmid}"],
            check=True
        )

        # 2️⃣ Migration à froid
        subprocess.run(
            ["ssh", f"root@{source_ip}", f"qm migrate {vmid} {target}"],
            check=True
        )

        return jsonify({
            "message": f"✅ VM {vmid} migrée vers {target} avec succès"
        })

    except subprocess.CalledProcessError as e:
        return jsonify({
            "message": f"❌ Erreur migration : {str(e)}"
        }), 500


# -------------------------------------------------------------------
# LOGS PROXMOX
# -------------------------------------------------------------------
@app.route("/logs/<node>")
def logs_node(node):
    ip = PVE_HOSTS.get(node)
    if not ip:
        return f"Node inconnu : {node}", 400

    cmd = "journalctl -n 50 --no-pager"

    try:
        out = subprocess.check_output(
            ["ssh", f"root@{ip}", cmd],
            text=True,
        )
        return out
    except Exception as e:
        return f"Erreur SSH : {e}", 500

# -------------------------------------------------------------------
# STORAGES
# -------------------------------------------------------------------
@app.route("/storages/<node>")
def list_storages(node):
    ip = PVE_HOSTS.get(node)
    if not ip:
        return jsonify({"error": "node inconnu"}), 400

    try:
        cmd = f"pvesh get /nodes/{node}/storage --output-format json"
        out = subprocess.check_output(["ssh", f"root@{ip}", cmd], text=True)
        return out
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
        )
        return result.returncode == 0
    except Exception:
        return False


def check_jenkins():
    return small_ping("192.168.1.62")


def check_ansible_host():
    return small_ping("192.168.1.134")


def check_graylog():
    return small_ping("192.168.1.172")


def check_docker():
    return small_ping("192.168.1.172")


def check_terraform_host():
    return small_ping("192.168.1.12")


def check_pve1():
    return small_ping("192.168.1.193")


def check_pve2():
    return small_ping("192.168.1.194")


def check_pve3():
    return small_ping("192.168.1.195")


@app.route("/status")
def status():
    return jsonify(
        {
            "jenkins": check_jenkins(),
            "ansible": check_ansible_host(),
            "terraform": check_terraform_host(),
            "graylog": check_graylog(),
            "docker": check_docker(),
            "pve1": check_pve1(),
            "pve2": check_pve2(),
            "pve3": check_pve3(),
        }
    )

# -------------------------------------------------------------------
# ANSIBLE AUTOMATION (PING / MAJ – EXISTANT)
# -------------------------------------------------------------------
@app.route("/ansible/run/<play>", methods=["POST"])
def ansible_run_play(play):
    """
    Utilisé par les boutons "Test ping Ansible" et "Mise à jour Ansible"
    dans le dashboard (JS → /ansible/run/ping ou /ansible/run/maj).
    """

    playbooks = {
        "ping": "/etc/ansible/ping.yml",
        "maj": "/etc/ansible/maj.yml",
    }

    if play not in playbooks:
        return jsonify({"success": False, "error": "Playbook inconnu"}), 400

    playbook_path = playbooks[play]

    try:
        result = subprocess.check_output(
            [
                "ssh",
                "root@192.168.1.134",
                f"ansible-playbook {playbook_path} -i /etc/ansible/inventory.ini",
            ],
            stderr=subprocess.STDOUT,
            text=True,
            timeout=300,
        )
        return jsonify({"success": True, "output": result})
    except subprocess.CalledProcessError as e:
        return jsonify({"success": False, "output": e.output})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# -------------------------------------------------------------------
# DÉPLOIEMENT ANSIBLE DE SOLUTIONS (Apache2, etc.)
# -------------------------------------------------------------------

@app.route("/ansible/deploy", methods=["GET"])
def ansible_deploy_menu():
    all_vms = []
    for node in PVE_NODES:
        for vm in list_vms(node):
            if vm.get("template"):
                continue
            vm["node"] = node
            all_vms.append(vm)

    return render_template(
        "ansible_deploy.html",
        vms=all_vms,
        solutions = [
            "Bootstrap",
            "Bind9",
            "Nginx",
            "Zabbix",
            "Graylog",
            "GLPI"
        ]

    )



# -------------------------------------------------------------------
# ANSIBLE : LANCEMENT DU DÉPLOIEMENT APACHE2
# -------------------------------------------------------------------

@app.route("/vm_ip/<node>/<int:vmid>")
def vm_ip(node, vmid):
    """
    Renvoie l'adresse IP détectée via QEMU Guest Agent.
    """
    try:
        r = requests.get(
            f"https://{PVE_NODES[node]['ip']}:8006/api2/json/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces",
            headers=HEADERS_PVE,
            verify=False,
            timeout=4
        )
        data = r.json().get("data", {})
        interfaces = data.get("result", [])

        for iface in interfaces:
            if "ip-addresses" in iface:
                for ip_info in iface["ip-addresses"]:
                    if ip_info.get("ip-address") and ip_info.get("ip-address-type") == "ipv4":
                        ip = ip_info["ip-address"]
                        if not ip.startswith("127"):
                            return jsonify({"ip": ip})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"ip": None})


@app.route("/ansible/run", methods=["POST"])
def ansible_deploy_run():
    target_ip = request.form.get("target_ip")
    solution = request.form.get("solution")

    if not target_ip or not solution:
        return "Erreur paramètres", 400

    inventory_path = "/etc/ansible/playbooks/inventory_webdeploy.ini"

    # 1️⃣ Génération de l'inventaire (sur le serveur Ansible)
    inventory_content = (
        "[target]\n"
        f"vm1 ansible_host={target_ip} ansible_user=root ansible_ssh_pass=1234\n"
    )

    subprocess.run(
        [
            "ssh",
            "root@192.168.1.134",
            f"echo '{inventory_content}' > {inventory_path}"
        ],
        text=True
    )

    playbooks = {
        "Bootstrap": "bootstrap.yml",
        "Bind9": "bind9.yml",
        "Nginx": "nginx.yml",
        "Zabbix": "zabbix.yml",
        "Graylog": "graylog.yml",
        "GLPI": "glpi.yml",
    }

    if solution not in playbooks:
        return "Solution inconnue", 400

    playbook = playbooks[solution]

    # 2️⃣ Lancer Ansible avec l'inventaire dédié
    result = subprocess.run(
        [
            "ssh",
            "root@192.168.1.134",
            "ansible-playbook",
            f"/etc/ansible/playbooks/{playbook}",
            "-i",
            inventory_path,
        ],
        capture_output=True,
        text=True,
    )

    return (
        "<pre>"
        + result.stdout
        + "\n"
        + result.stderr
        + "</pre>"
    )


# -------------------------------------------------------------------
# AUTHENTIFICATION (LOGIN + 2FA)
# -------------------------------------------------------------------
ADMIN_USERNAME = "nebtech_admin_231177"
ADMIN_PASSWORD = "Nbtawyhtp@@1977"
TOTP_SECRET = pyotp.random_base32()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if (
            request.form.get("username") == ADMIN_USERNAME
            and request.form.get("password") == ADMIN_PASSWORD
        ):
            session["pre_2fa"] = True
            return redirect("/2fa")

        flash("Identifiants invalides", "error")

    return render_template("login.html")


@app.route("/2fa", methods=["GET", "POST"])
def twofa():
    if "pre_2fa" not in session:
        return redirect("/login")

    totp = pyotp.TOTP(TOTP_SECRET)

    if request.method == "POST":
        if totp.verify(request.form.get("code")):
            session["user"] = ADMIN_USERNAME
            session.pop("pre_2fa", None)
            return redirect("/")
        flash("Code incorrect", "error")

    return render_template("2fa.html")


@app.route("/2fa_qr")
def twofa_qr():
    totp = pyotp.TOTP(TOTP_SECRET)
    uri = totp.provisioning_uri(
        name="NebTech_Admin", issuer_name="NebTech Dashboard"
    )

    import qrcode
    import io
    from flask import send_file

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# -------------------------------------------------------------------
# API GROUPES
# -------------------------------------------------------------------
@app.route("/groups", methods=["GET"])
def get_groups():
    return jsonify({"groups": DEPLOYMENT_GROUPS})


@app.route("/groups/create", methods=["POST"])
def create_group():
    global DEPLOYMENT_GROUPS

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    modules = data.get("modules") or []

    if not name:
        return jsonify({"success": False, "error": "Nom de groupe manquant"}), 400
    if not modules:
        return jsonify({"success": False, "error": "Aucun template sélectionné"}), 400

    valid_modules = [m for m in modules if m in TEMPLATES_INFO]
    if not valid_modules:
        return jsonify({"success": False, "error": "Templates invalides"}), 400

    DEPLOYMENT_GROUPS[name] = valid_modules
    save_groups(DEPLOYMENT_GROUPS)

    return jsonify({"success": True})

# -------------------------------------------------------------------
# TERRAFORM ÉPHÉMÈRE (1 VM)
# -------------------------------------------------------------------
def create_tf_project(vars_dict):
    temp_dir = tempfile.mkdtemp(prefix="tf-job-")

    main_tf = """
    terraform {
      required_providers {
        proxmox = {
          source  = "bpg/proxmox"
          version = "0.87.0"
        }
      }
    }

    module "vm" {
      source = "/etc/terraform/cloud-project/modules/vm_generic"

      vm_id             = var.vm_id
      vm_name           = var.vm_name
      node              = var.node
      template_id       = var.template_id
      cpu               = var.cpu
      sockets           = var.sockets
      ram               = var.ram
      disk              = var.disk
      datastore         = var.datastore
      bridge            = var.bridge
      cloudinit_storage = var.cloudinit_storage
    }
    """

    provider_tf = """
    provider "proxmox" {
      endpoint = "https://192.168.1.193:8006/"
      insecure = true
      username = "root@pam"
      password = "Nbtawyhtp@@1977"
    }
    """

    variables_tf = """
    variable "vm_id" {}
    variable "vm_name" {}
    variable "node" {}
    variable "template_id" {}
    variable "cpu" {}
    variable "sockets" {}
    variable "ram" {}
    variable "disk" {}
    variable "datastore" {}
    variable "bridge" {}
    variable "cloudinit_storage" {}
    """

    tfvars = ""
    for k, v in vars_dict.items():
        if isinstance(v, str):
            tfvars += f'{k} = "{v}"\n'
        else:
            tfvars += f"{k} = {v}\n"

    open(os.path.join(temp_dir, "main.tf"), "w").write(main_tf)
    open(os.path.join(temp_dir, "provider.tf"), "w").write(provider_tf)
    open(os.path.join(temp_dir, "variables.tf"), "w").write(variables_tf)
    open(os.path.join(temp_dir, "terraform.tfvars"), "w").write(tfvars)

    def run(cmd):
        process = subprocess.run(
            cmd,
            cwd=temp_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        return process.stdout

    output = "\n===== TERRAFORM INIT =====\n"
    output += run(["terraform", "init", "-upgrade"])

    output += "\n===== TERRAFORM APPLY =====\n"
    output += run(["terraform", "apply", "-auto-approve"])

    shutil.rmtree(temp_dir, ignore_errors=True)

    return output

# -------------------------------------------------------------------
# TERRAFORM ÉPHÉMÈRE (GROUPE MULTI-VM)
# -------------------------------------------------------------------
def create_tf_project_group(group_vm_list):
    temp_dir = tempfile.mkdtemp(prefix="tf-group-")

    terraform_block = """
terraform {
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "0.87.0"
    }
  }
}

provider "proxmox" {
  endpoint = "https://192.168.1.193:8006/"
  insecure = true
  username = "root@pam"
  password = "Nbtawyhtp@@1977"
}
"""

    modules_block = ""

    for idx, vm in enumerate(group_vm_list, start=1):
        modules_block += f"""
module "vm_{idx}" {{
  source = "/etc/terraform/cloud-project/modules/vm_generic"

  vm_id             = {vm["vm_id"]}
  vm_name           = "{vm["vm_name"]}"
  node              = "{vm["node"]}"
  template_id       = {vm["template_id"]}
  cpu               = {vm["cpu"]}
  sockets           = {vm["sockets"]}
  ram               = {vm["ram"]}
  disk              = {vm["disk"]}
  datastore         = "{vm["datastore"]}"
  bridge            = "{vm["bridge"]}"
  cloudinit_storage = "{vm["cloudinit_storage"]}"
}}
"""

    main_tf_content = terraform_block + "\n" + modules_block
    with open(os.path.join(temp_dir, "main.tf"), "w") as f:
        f.write(main_tf_content)

    def run(cmd):
        process = subprocess.run(
            cmd,
            cwd=temp_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        return process.stdout

    output = "\n===== TERRAFORM INIT (GROUPE) =====\n"
    output += run(["terraform", "init", "-upgrade"])

    output += "\n===== TERRAFORM APPLY (GROUPE) =====\n"
    output += run(["terraform", "apply", "-auto-approve"])

    shutil.rmtree(temp_dir, ignore_errors=True)

    return output

# -------------------------------------------------------------------
# DASHBOARD PRINCIPAL
# -------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    if "user" not in session:
        return redirect("/login")

    output = ""

    form = {
        "vm_name": "vm-demo",
        "vm_id": "200",
        "node": "pve01",
        "template_id": "300",
        "cpu": "2",
        "ram": "4096",
        "disk": "30",
        "bridge": "vmbr0",
        "datastore": "vmstore",
        "cloudinit_storage": "vmstore",
        "sockets": "1",
    }

    if request.method == "POST":
        module = request.form.get("module", "")

        for k in form:
            form[k] = request.form.get(k, form[k])

        # CAS 2 : GROUPE
        if module.startswith("group_"):
            group_name = module.replace("group_", "", 1)

            if group_name not in DEPLOYMENT_GROUPS:
                output = f"Groupe inconnu : {group_name}"
            else:
                template_keys = DEPLOYMENT_GROUPS[group_name]

                try:
                    base_vm_id = int(form["vm_id"])
                    base_name = form["vm_name"] or "groupvm"
                    cpu = int(form["cpu"])
                    ram = int(form["ram"])
                    disk = int(form["disk"])
                    sockets = int(form["sockets"])
                    node = form["node"]
                    bridge = form["bridge"]
                    datastore = form["datastore"]
                    cloudinit = form["cloudinit_storage"]
                except (ValueError, TypeError) as e:
                    output = f"Erreur valeurs groupe : {e}"
                else:
                    group_vm_list = []
                    current_id = base_vm_id

                    for tpl_key in template_keys:
                        tpl = TEMPLATES_INFO.get(tpl_key)
                        if not tpl:
                            continue

                        group_vm_list.append(
                            {
                                "vm_id": current_id,
                                "vm_name": f"{base_name}-{current_id}",
                                "node": node,
                                "template_id": tpl["template_id"],
                                "cpu": cpu,
                                "ram": ram,
                                "disk": disk,
                                "bridge": bridge,
                                "datastore": datastore,
                                "cloudinit_storage": cloudinit,
                                "sockets": sockets,
                            }
                        )

                        current_id += 1

                    output = create_tf_project_group(group_vm_list)

        # CAS 1 : VM UNIQUE
        else:
            if module not in TEMPLATES_INFO:
                output = f"Template inconnu : {module}"
            else:
                tpl = TEMPLATES_INFO[module]

                try:
                    vars_dict = {
                        "vm_id": int(form["vm_id"]),
                        "vm_name": form["vm_name"],
                        "node": form["node"],
                        "template_id": tpl["template_id"],
                        "cpu": int(form["cpu"]),
                        "ram": int(form["ram"]),
                        "disk": int(form["disk"]),
                        "bridge": form["bridge"],
                        "datastore": form["datastore"],
                        "cloudinit_storage": form["cloudinit_storage"],
                        "sockets": int(form["sockets"]),
                    }
                except (ValueError, TypeError) as e:
                    output = (
                        "Erreur dans les valeurs du formulaire "
                        f"(conversion en entier) : {e}"
                    )
                else:
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
# RUN
# -------------------------------------------------------------------
#if __name__ == "__main__":
#    app.run(host="0.0.0.0", port=443, ssl_context=("dashboard.pem", "dashboard.key"))

# MODIFICATION 24.01.2026
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=443,
        ssl_context=("dashboard.pem", "dashboard.key"),
        debug=True
    )
