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

![Screenshot der Applikation, ein Text wurde ins Eingabefeld zum Verschlüsseln eingetippt, man sieht das verschlüsselte Ergebnis sowie den Button 'Copy' h:500](assets/Screenshot%201.png)

---

## Technologien

- .NET Razor Pages für die Web App selbst
- Bereitstellung in der Cloud als Azure Web App
- Development-Secrets mit .NET Secrets
- Production Secrets mit Azure Key Vault

---

## CI / CD

- Codeverwaltung auf GitHub
- GitHub Actions - CI/CD:
  - Automatische Deployments zu Azure
  - Automatische Releases auf GitHub
  - Automatische Dependency-Updates mit Dependabot

---

## Architektur

![Architektur der App und des Ökosystems h:500](assets/Architektur.png)

---

## Probleme

Probleme mit Azure Secrets =>
falsche Benennung (Großbuchstaben)

Probleme beim Aufsetzen der GitHub Release Action =>
unklare Dokumentation, fehlerhafte Guides im Internet

---

## Quellen

- [Marp - Markdown Presentation Framework](https://marp.app/)
- [Microsoft .NET](https://dotnet.microsoft.com/en-us/)
- [Microsoft Azure](https://azure.microsoft.com/)
- [GitHub](https://github.com/)
  - [Super Linter](https://github.com/super-linter/super-linter)
  - [git-auto-commit Action](https://github.com/stefanzweifel/git-auto-commit-action)
  - [Semantic Release Action](https://github.com/cycjimmy/semantic-release-action)

---

## Links für mein Projekt

- [Azure Web App](https://secure-notes-ccde-bkaedpeghqeaaqh6.polandcentral-01.azurewebsites.net/)
- [GitHub Repo](https://github.com/Bryx-taffid/ccde-demo)
