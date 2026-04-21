# NebTech Cloud Dashboard

Dashboard web de gestion d’infrastructure conçu dans le cadre d’un projet de fin d’étude :
**“Mise en place d’un Cloud privé”**

---

## Présentation

NebTech Cloud Dashboard est une interface centralisée permettant de piloter et automatiser une infrastructure basée sur :

* **Proxmox VE** (virtualisation & gestion des VMs)
* **Terraform** (déploiement d’infrastructure)
* **Ansible** (automatisation & configuration)
* **Monitoring & logs** (Graylog, métriques système)

L’objectif est de fournir un outil simple, visuel et efficace pour gérer un environnement cloud privé.

---

## Fonctionnalités principales

* Authentification sécurisée avec 2FA
* Monitoring temps réel des nœuds Proxmox
* Déploiement de machines virtuelles via Terraform
* Gestion de groupes de déploiement
* Automatisation Ansible (ping, mise à jour, déploiement)
* Consultation des logs Proxmox via SSH
* Actions sur les VMs (start, stop, reset, suppression, migration)
* Accès rapide aux outils (Jenkins, Graylog, etc.)

---

## Configuration

Les informations sensibles (IP, tokens, mots de passe) sont externalisées via des variables d’environnement.

Copier le fichier `.env.example` :

```bash
cp .env.example .env
```

Puis renseigner les valeurs selon votre environnement.

---

## Lancement

```bash
pip install -r requirements.txt
python app.py
```

---

## Sécurité

Ce projet est publié dans une version **nettoyée** :

* Aucune donnée sensible incluse
* Utilisation de variables d’environnement
* Bonnes pratiques respectées pour un usage public

---

## Auteur

Projet réalisé par **Damien RECULE**
Dans le cadre d’un projet de fin d’étude en infrastructure & cloud.

---

## Objectif

Ce projet a pour but de démontrer :

* des compétences en **DevOps**
* la maîtrise des outils **cloud & automatisation**

------------------------------------------------------

Arborescence du projet Dashboard NebTech
Structure globale du projet
'''
/opt/nebtech-dashboard/
│
├── app.py                  # Application Flask principale
├── requirements.txt        # Dépendances Python
├── config/
│   ├── settings.py         # Variables globales (IP, tokens, etc.)
│   └── secrets.env         # Variables sensibles
├── templates/              # Templates HTML (Jinja2)
│   ├── index.html
│   ├── login.html
│   ├── 2fa.html
│   ├── ansible_deploy.html
│   └── no_cert.html
│
├── static/                 # Fichiers statiques
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   └── app.js
│   ├── images/
│   │   └── logo.png
│   └── background.jpg
│
├── modules/                # Logique métier
│   ├── proxmox.py
│   ├── ansible.py
│   ├── terraform.py
│   └── monitoring.py
│
├── logs/                   # Logs applicatifs
│   └── dashboard.log
│

Partie système (serveur Debian)
Intégration DevOps
Terraform
/etc/terraform/
│
└── cloud-project/
    ├── modules/
    │   └── vm_generic/
    └── environments/
        └── production/
            └── groups.json

Ansible
/etc/ansible/
│
├── playbooks/
│   ├── bootstrap.yml
│   ├── nginx.yml
│   ├── zabbix.yml
│   └── glpi.yml
 |     |── ……
│
└── inventory.ini


Infrastructure complète Graylog
/infra/
│
├── proxmox-cluster/
│   ├── pve01
│   ├── pve02
│   └── pve03
│
├── storage/
│   └── ceph (OSD + MON + MGR)
│
├── vm-services/
│   ├── terraform-vm (Debian)
│   ├── ansible-vm (Debian)
│   ├── jenkins-vm (Debian)
│   ├── graylog-vm (Debian)
│   ├── dashboard-vm (Debian)
│   └── pbs-vm (backup)

Serveur Jenkins
Arborescence
/var/lib/jenkins/
│
├── jobs/
│   └── infra-pipeline/
│       └── config.xml
│
├── workspace/
│   └── infra-pipeline/
│       └── Jenkinsfile
│
├── plugins/
├── secrets/
└── logs/
'''

Flux d’accès au dashboard.
Utilisateur
   ↓
https://dashboard.novatechsolutions.fr
   ↓
(mTLS + HTTPS)
   ↓
Flask (app.py)
   ↓
Proxmox / Ansible / Terraform

* la capacité à concevoir une **plateforme complète de gestion d’infrastructure**

---
