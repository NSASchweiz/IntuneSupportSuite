# Intune Support Suite

Die **Intune Support Suite** ist ein PowerShell-basiertes Support- und Analyse-Toolset für Microsoft Intune verwaltete Windows-Clients.

Ziel der Suite ist es, typische Support-, Diagnose- und Troubleshooting-Aufgaben rund um Intune, Company Portal, Gerätestatus, Richtlinien, Applikationsinstallationen und lokale Client-Konfigurationen schneller, nachvollziehbarer und standardisierter durchzuführen.

Ich arbeite aktuell mit Intune als PoC. Mit diesem Tool wollte ich mir das Sammeln und Analysieren von Fehlern, Logs, etc. vereinfachen und zentralisieren. Ich bin kein Programmierer, weshalb ich darauf hinweisen möchte, dass dieses Projekt mit Code Vibing entstanden ist.

## Zweck

In Intune-verwalteten Umgebungen sind viele relevante Informationen über verschiedene Stellen verteilt: Windows Registry, Event Logs, lokale Intune Management Extension Logs, installierte Anwendungen, Gerätestatus, Benutzerkontext und Cloud-Zuweisungen.

Die Intune Support Suite bündelt relevante Prüfungen und Hilfsfunktionen in einem zentralen Werkzeug, damit Support- und Engineering-Teams schneller erkennen können, wo ein Problem liegt.

## Funktionen

Die Suite kann je nach Ausbaustand unter anderem folgende Bereiche unterstützen:

- Prüfung des Intune-Registrierungsstatus
- Analyse der Microsoft Intune Management Extension
- Auslesen relevanter Intune- und Autopilot-Informationen
- Prüfung installierter Anwendungen
- Analyse von Win32-App-Installationen
- Auswertung lokaler Logdateien
- Prüfung von Gerätekonfigurationen
- Unterstützung bei Company-Portal-Problemen
- Sammlung technischer Diagnosedaten
- Standardisierte Ausgabe für Supportfälle

## Typische Einsatzfälle

Die Intune Support Suite ist gedacht für:

- 1st-Level- und 2nd-Level-Support
- Client Engineering
- Workplace Engineering
- Intune-Betrieb
- Fehleranalyse bei Softwareverteilungen
- Analyse von Richtlinien- oder Compliance-Problemen
- Vorbereitung von Eskalationen

## Voraussetzungen

- Windows 10 oder Windows 11
- Microsoft Intune verwalteter Client
- PowerShell 5.1 oder neuer
- Lokale Benutzer- oder Administratorrechte, abhängig von der ausgeführten Funktion
- Zugriff auf lokale Logs und Systeminformationen

## Installation

1) Repository klonen
2) .\Scripts\custompacker_git.ps1 (edit paths if needed!)
3) make sure you have a valid code signing certificate imported
4) run custompacker_git.ps1
   a) it will sign all ps1 and exe
   b) it will build the project
   c) it will sign the new exe
   d) it will add a catalog for the trustedconfig.json to be valid
   e) if .\Assets\file.ico is available, it will be set as program icon
6) if you have to change trustedconfig.json after you built the project, use retrustconfig.ps1 or just build it newly. otherwise the trust cant be verificated and the program will only run in simulation mode

## Insights
<img width="1366" height="814" alt="Screenshot 2026-04-27 124914" src="https://github.com/user-attachments/assets/00255bff-2498-4453-990e-7ea6b0419e72" />
<img width="1368" height="814" alt="Screenshot 2026-04-27 124837" src="https://github.com/user-attachments/assets/7ecd5b4f-75bf-4713-b064-d9aec8d3be43" />
<img width="1368" height="814" alt="Screenshot 2026-04-27 124754" src="https://github.com/user-attachments/assets/8dcf4bdb-1849-4884-923f-fee313ac7bbc" />
<img width="964" height="852" alt="Screenshot 2026-04-27 125150" src="https://github.com/user-attachments/assets/181c6e6a-51e5-4f47-b70c-72c0d2b5fc1b" />
<img width="966" height="853" alt="Screenshot 2026-04-27 125127" src="https://github.com/user-attachments/assets/275ed7a8-d93f-4c82-999f-eb559ee0fd9f" />
<img width="1474" height="823" alt="Screenshot 2026-04-27 125109" src="https://github.com/user-attachments/assets/5d0a1f2a-4668-47ed-bec2-4e466999e0a7" />
<img width="1511" height="826" alt="Screenshot 2026-04-27 125058" src="https://github.com/user-attachments/assets/1dd40c56-e086-4367-acff-232edbdcc7ab" />
<img width="1367" height="815" alt="Screenshot 2026-04-27 125039" src="https://github.com/user-attachments/assets/585829eb-3914-45c5-9eac-739e093ac575" />
<img width="1367" height="814" alt="Screenshot 2026-04-27 125024" src="https://github.com/user-attachments/assets/1176b113-4783-4b92-b449-418fbbf07524" />
<img width="1367" height="814" alt="Screenshot 2026-04-27 125009" src="https://github.com/user-attachments/assets/d55311d0-43fe-4d66-883b-73813ecf1d5b" />
<img width="1369" height="816" alt="Screenshot 2026-04-27 124951" src="https://github.com/user-attachments/assets/83a4632d-71eb-4a3d-8fa5-27f45867969d" />
<img width="1366" height="815" alt="Screenshot 2026-04-27 124938" src="https://github.com/user-attachments/assets/c73e29b1-d544-458f-b773-74e307f482c1" />
