#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NebTech Cloud Dashboard
Auteur : Damien RECULE
Version : 3.2 (Clean GitHub Version)
"""

from flask import Flask, render_template, request, redirect, session, flash, jsonify
import subprocess
import os
import secrets
import pyotp
import requests
import json
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings()

# -------------------------------------------------------------------
# LOAD ENV
# -------------------------------------------------------------------
load_dotenv()

# -------------------------------------------------------------------
# FLASK APP
# -------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", secrets.token_hex(32))

# -------------------------------------------------------------------
# CONFIG PROXMOX
# -------------------------------------------------------------------
PVE_NODES = {
    "pve01": {"ip": os.getenv("PVE1_IP"), "name": "pve01"},
    "pve02": {"ip": os.getenv("PVE2_IP"), "name": "pve02"},
    "pve03": {"ip": os.getenv("PVE3_IP"), "name": "pve03"},
}

PVE_TOKEN_ID = os.getenv("PVE_TOKEN_ID")
PVE_SECRET = os.getenv("PVE_SECRET")

HEADERS_PVE = {
    "Authorization": f"PVEAPIToken={PVE_TOKEN_ID}={PVE_SECRET}"
}

# -------------------------------------------------------------------
# AUTH CONFIG
# -------------------------------------------------------------------
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
TOTP_SECRET = os.getenv("TOTP_SECRET", pyotp.random_base32())

# -------------------------------------------------------------------
# UTILS
# -------------------------------------------------------------------
def ping_host(ip):
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except Exception:
        return False


def proxmox_api(url):
    try:
        r = requests.get(url, headers=HEADERS_PVE, verify=False, timeout=5)
        r.raise_for_status()
        return r.json()["data"]
    except Exception as e:
        print("API error:", e)
        return None


# -------------------------------------------------------------------
# MONITORING
# -------------------------------------------------------------------
@app.route("/monitor/<node>")
def monitor(node):
    if node not in PVE_NODES:
        return jsonify({"error": "node inconnu"}), 400

    ip = PVE_NODES[node]["ip"]

    if not ping_host(ip):
        return jsonify({"online": False})

    data = proxmox_api(f"https://{ip}:8006/api2/json/nodes/{node}/status")

    if not data:
        return jsonify({"online": True})

    return jsonify({
        "online": True,
        "cpu": round(data["cpu"] * 100, 1),
        "ram": round(data["memory"]["used"] / data["memory"]["total"] * 100, 1),
        "disk": round(data["rootfs"]["used"] / data["rootfs"]["total"] * 100, 1),
    })


# -------------------------------------------------------------------
# VM LIST
# -------------------------------------------------------------------
@app.route("/vms/<node>")
def list_vms(node):
    if node not in PVE_NODES:
        return jsonify([])

    ip = PVE_NODES[node]["ip"]
    data = proxmox_api(f"https://{ip}:8006/api2/json/nodes/{node}/qemu")

    return jsonify(data or [])


# -------------------------------------------------------------------
# VM ACTIONS
# -------------------------------------------------------------------
@app.route("/vm/<node>/<vmid>/<action>", methods=["POST"])
def vm_action(node, vmid, action):
    if action not in ["start", "stop", "reset"]:
        return jsonify({"error": "action invalide"}), 400

    ip = PVE_NODES[node]["ip"]

    try:
        requests.post(
            f"https://{ip}:8006/api2/json/nodes/{node}/qemu/{vmid}/status/{action}",
            headers=HEADERS_PVE,
            verify=False,
        )
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


# -------------------------------------------------------------------
# LOGIN + 2FA
# -------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if (
            request.form.get("username") == ADMIN_USERNAME
            and request.form.get("password") == ADMIN_PASSWORD
        ):
            session["pre_2fa"] = True
            return redirect("/2fa")

        flash("Identifiants invalides")

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

        flash("Code invalide")

    return render_template("2fa.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# -------------------------------------------------------------------
# HOME
# -------------------------------------------------------------------
@app.route("/")
def index():
    if "user" not in session:
        return redirect("/login")

    return render_template("index.html")


# -------------------------------------------------------------------
# RUN
# -------------------------------------------------------------------
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=443,
        ssl_context=("dashboard.pem", "dashboard.key"),
        debug=True
    )
