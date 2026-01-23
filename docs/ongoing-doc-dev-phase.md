---
marp: true
theme: gaia
class: lead
paginate: true
backgroundColor: #fff
backgroundImage: "url('https://marp.app/assets/hero-background.svg')"
---

# **CCDE Project**

By David Bruckmüller

---

## Applikation

### Ziel und Funktionen

- Secure Notes App, wo Text ver- und entschlüsselt werden kann
- Modernes Design mit White/Dark-Mode

---

### Screenshots

**TODO**

---

## Technologien

- .NET Razor Pages für die Web App selbst
- Bereitstellung in der Cloud als Azure Web App
- Development-Secrets mit .NET Secrets
- Production Secrets mit Azure Key Vault

---

## Technologien - Fortsetzung

- Codeverwaltung auf GitHub
- GitHub Actions - CI/CD:
  - Automatische Deployments zu Azure
  - Automatische Releases auf GitHub
  - Automatische Dependency-Updates mit Dependabot

---

## Architektur

Original h:500
![h:250](assets/Architektur.png)

**Es fehlt: GH Release**

---

## Probleme

Probleme mit Azure Secrets =>
falsche Benennung (Großbuchstaben)

Probleme beim Aufsetzen der GitHub Release Action =>
unklare Dokumentation, fehlerhafte Guides im Internet
