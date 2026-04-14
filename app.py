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
import socket

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
    "pve01": {"ip": "IP_NOEUD_001", "name": "pve01"},
    "pve1": {"ip": "IP_NOEUD_001"name": "pve01"},

    "pve02": {"ip": "IP_NOEUD_002", "name": "pve02"},
    "pve2": {"ip": "IP_NOEUD_002", "name": "pve02"},

    "pve03": {"ip": "IP_NOEUD_003", "name": "pve03"},
    "pve3": {"ip": "IP_NOEUD_003", "name": "pve03"},
}

PVE_HOSTS = {
    "pve01": "IP_NOEUD_001",
    "pve1": "IP_NOEUD_001",

    "pve02": "IP_NOEUD_002",
    "pve2": "IP_NOEUD_002",

    "pve03": "IP_NOEUD_003",
    "pve3": "IP_NOEUD_003",
}

PVE_TOKEN_ID = "root@pam!<nom_du_token>"
PVE_SECRET = "<PVE_TOKEN_ID>"

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
}

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


import subprocess
import time
import platform

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
        )

        if out.returncode == 0:
            return round((time.time() - start) * 1000, 1)

    except Exception as e:
        print("Ping error:", e)

    return None


@app.route("/monitor/<node>")
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

        return {
            "online": True,
            "ping": latency,  # peut être None !
            "cpu": cpu,
            "ram": ram,
            "disk": disk,
            "vm": len(vms),
        }

    except Exception as e:
        print("API error:", e)
        return {
            "online": False,
            "ping": latency,
        }

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
    return small_ping("IP_JENKINS")


def check_ansible_host():
    return small_ping("IP_ANSIBLE")


def check_graylog():
    return small_ping("IP_GRAYLOG")


def check_docker():
    return small_ping("IP_DOCKER")


def check_terraform_host():
    return small_ping("IP_TERRAFORM")


def check_pve1():
    return small_ping("IP_NOEUD_001")


def check_pve2():
    return small_ping("IP_NOEUD_002")


def check_pve3():
    return small_ping("IP_NOEUD_003")


@app.route("/status")
def status():
    return jsonify({
        "terraform": True,
        "ansible": True,
        "jenkins": True,
        "graylog": True,
        "docker": True,

        # ✅ IMPORTANT : utiliser get_pve_stats
        "pve1": get_pve_stats("pve01")["online"],
        "pve2": get_pve_stats("pve02")["online"],
        "pve3": get_pve_stats("pve03")["online"],
    })

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
                "root@<IP_ANSIBLE>",
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
        solutions=["Apache2"]
    )
##
@app.route("/test")
def test():
    return "OK"
##
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
    vmid = request.form.get("vm")
    target_ip = request.form.get("target_ip")
    solution = request.form.get("solution")

    if not vmid:
        return "<h3>❌ Erreur : aucune VM sélectionnée</h3>"

    if not target_ip:
        return "<h3>❌ Erreur : aucune IP cible fournie</h3>"

    # INVENTORY créé directement sur le serveur ANSIBLE
    ssh_inventory = (
        f"echo '[web]' > /etc/ansible/inventory_webdeploy.ini && "
        f"echo 'target ansible_host={target_ip} ansible_user=root ansible_ssh_pass=1234' "
        f">> /etc/ansible/inventory_webdeploy.ini"
    )

    # 1) Écriture de l’inventaire sur le serveur Ansible
    subprocess.run(
        ["ssh", "root@<IP_ANSIBLE>", ssh_inventory],
        text=True
    )

    # 2) Sélection du playbook
    playbooks = {
        "Apache2": "/etc/ansible/playbooks/apache.yml"
    }

    if solution not in playbooks:
        return "<h3>❌ Erreur : solution inconnue</h3>"

    playbook = playbooks[solution]

    # 3) Lancement du playbook depuis le serveur ANSIBLE
    cmd = (
        f"ansible-playbook -i /etc/ansible/inventory_webdeploy.ini {playbook}"
    )

    try:
        result = subprocess.check_output(
            ["ssh", "root@<IP_ANSIBLE>", cmd],
            stderr=subprocess.STDOUT,
            text=True
        )
        return f"<pre>{result}</pre>"

    except subprocess.CalledProcessError as e:
        return f"<pre>❌ Erreur Ansible :\n{e.output}</pre>"

    except Exception as e:
        return f"<pre>❌ Erreur Python : {str(e)}</pre>"

# -------------------------------------------------------------------
# AUTHENTIFICATION (LOGIN + 2FA)
# -------------------------------------------------------------------
ADMIN_USERNAME = "<ADMIN_USERNAME>"
ADMIN_PASSWORD = "<ADMIN_PASSWORD>"
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

provider "proxmox" {
  endpoint = "https://<NOEUD_001>:8006/"
  insecure = true
  username = "root@pam"
  password = "<PASSWORD>"
}

resource "proxmox_virtual_environment_vm" "vm" {
  vm_id     = var.vm_id
  name      = var.vm_name
  node_name = var.node

  clone {
    vm_id = var.template_id
  }

  cpu {
    cores = var.cpu
  }

  memory {
    dedicated = var.ram
  }

  disk {
    interface = "scsi0"
    size      = var.disk
  }

  network_device {
    bridge = var.bridge
  }

  agent {
    enabled = true
  }
}
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
"""

    tfvars = ""
    for k, v in vars_dict.items():
        if isinstance(v, str):
            tfvars += f'{k} = "{v}"\n'
        else:
            tfvars += f"{k} = {v}\n"

    open(os.path.join(temp_dir, "main.tf"), "w").write(main_tf)
    open(os.path.join(temp_dir, "variables.tf"), "w").write(variables_tf)
    open(os.path.join(temp_dir, "terraform.tfvars"), "w").write(tfvars)

    import shutil
    shutil.rmtree(os.path.join(temp_dir, ".terraform"), ignore_errors=True)

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
  endpoint = "https://<IP_NOEUD_001>:8006/"
  insecure = true
  username = "root@pam"
  password = "<PASSWORD>"
}
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

    with open(os.path.join(temp_dir, "main.tf"), "w") as f:
        f.write(main_tf)

    import shutil
    shutil.rmtree(os.path.join(temp_dir, ".terraform"), ignore_errors=True)

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
            try:
                vars_dict = {
                    "vm_id": int(form["vm_id"]),
                    "vm_name": form["vm_name"],
                    "node": form["node"],
                    "template_id": int(form["template_id"]),
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
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=443, ssl_context=("dashboard.pem", "dashboard.key"))
