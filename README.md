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
* la capacité à concevoir une **plateforme complète de gestion d’infrastructure**

---
