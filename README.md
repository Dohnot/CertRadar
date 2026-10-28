# CertRadar 0.2 – lokaler Zertifikats-Explorer

Ein **lauffähiger MVP** für die spätere Kurserstellung: öffentlich dokumentierte TLS-Zertifikatsausstellungen per crt.sh entdecken, Namen/Aussteller/Gültigkeitsdaten einordnen und explizit erfasste öffentliche TLS-Endpunkte überprüfen.

## Start (Linux, macOS, Windows)

Python **3.10+** erforderlich, **keine pip-Abhängigkeiten**.

```bash
python3 app.py
```

Unter Windows alternativ `py app.py`. Anschließend im Browser **http://127.0.0.1:8765** öffnen. Beenden mit `Strg+C`. Alternativer Port: `python3 app.py --port 8766`.

Zum Testen zunächst **„Demo laden“** auswählen (benötigt kein Internet). Für crt.sh eine Domain oder eine vollständige `https://`-URL eingeben und **„crt.sh durchsuchen“** wählen. TLS-Endpunkte auf der Registerkarte **„TLS-Inventar“** manuell hinzufügen und einzeln prüfen.

## Funktionen
- CT-Suche nach Hauptdomain **und** `%.domain.tld` über `crt.sh` (öffentliches JSON-Endpoint), 1 Stunde lokal gecacht; begrenzte Response-Größe.
- Deduplizierung nach der von crt.sh gelieferten ID, CSV-Export, tabellarische Darstellung (max. 300 im Browser, bis zu 5.000 im Export).
- Lokales Endpunktinventar mit Host, Port und Ansprechpartner (`data/inventory.json`).
- TLS-Live-Verbindung mit standardmäßiger Zertifikats-/Hostname-Validierung, bei erfolgreichem Handshake werden Ablaufdatum, Issuer und TLS-Version angezeigt.
- Ohne externe Python-Pakete; lokale UI auf `127.0.0.1`.

## Wichtige Grenzen
- **crt.sh zeigt Zertifikatsausstellungen, keine installierten Zertifikate.** CT ist historisch, mehrfache Einträge, Precertificates und Erneuerungen sind möglich. Nicht alle aktiven Systeme und interne Zertifizierungsstellen erscheinen dort.
- Die Anzeige „historisch abgelaufen“ beruht ausschließlich auf dem Not-After-Datum eines CT-Datensatzes. Dies sagt nichts darüber aus, ob ein Endpunkt das Zertifikat noch ausliefert.
- **Live-TLS-Checks** prüfen nur explizit eingetragene, **öffentlich auflösbare** Domainnamen. Keine Portscans, keine massenhaften Tests, kein internes Netzwerk. **Nur eigene oder autorisierte Endpunkte prüfen.** DNS-Rebinding-Schutz ist im MVP nicht vollständig (erneute DNS-Auflösung beim TLS-Connect ist vermieden, aber dies ersetzt kein gehärtetes Netzwerk-Sandboxing).
- Bei abgelaufenen/nicht vertrauenswürdigen Zertifikaten scheitert die Standardvalidierung. Die App zeigt die Fehlermeldung statt eine ungeprüfte Ablaufzeit auszugeben.
- Keine Alarmierung, keine Jobs, kein Rechtekonzept, keine Migrationen, keine zentrale Persistenz, keine CA-/ACME-Integration. **Nicht für produktionskritischen Einsatz** und nicht über einen Reverse Proxy öffentlich bereitstellen.
- crt.sh ist ein externer Dienst. Der Abruf kann scheitern, langsam sein oder wegen Antwortgrößenbegrenzung abbrechen. Der Prototyp besitzt keine Garantie für Vollständigkeit.

## Nächste Ausbaustufen
1. CT-Einträge mit echten TLS-Endpunkten korrelieren (mit konkreter Freigabe).
2. Historie und Priorisierung (unbekannte/neu auftauchende Namen) mit SQLite.
3. Wiederkehrende Checks, Warnschwellen und Alarmierung via Icinga/SMTP/Webhook.
4. Private CA-/PKI-Datenquellen und ACME-Renewal-Status.
5. Tests, Authentisierung, Deployment-Härtung.

### Datenschutz und Berechtigungen
Die Daten liegen im `data/`-Verzeichnis. Keine externe Telemetrie. Nur die eingegebene Domain wird bei einer echten CT-Suche an crt.sh übermittelt. Bei Live-TLS-Checks baut CertRadar Netzwerkverbindungen zu den registrierten Endpunkten auf.

## Fehlerbehebung (v0.2)
- Vollständige URLs wie `https://theater-in-essen.de/` werden akzeptiert.
- Eine Apex-Domain wird zusätzlich zur Subdomainsuche abgefragt.
- Der alte Cache der v0.1 wird automatisch verworfen.
- Der crt.sh-Dienst muss erreichbar sein; leere CT-Ergebnisse bedeuten **nicht**, dass eine Website kein aktives Zertifikat hat. Für dessen Live-Prüfung den Endpunkt ins Inventar aufnehmen.
