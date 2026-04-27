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
