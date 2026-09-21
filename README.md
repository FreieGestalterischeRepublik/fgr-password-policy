# FGR Password Policy

Ein WordPress-Plugin der [Freien Gestalterischen Republik](https://fgr.design).

Erzwingt sichere Passwörter für ausgewählte Benutzerrollen — ohne Werbung, Upsells oder Fremd-Branding.

## Funktionen

- Passwort-Kriterien frei konfigurierbar: Mindestlänge, Groß-/Kleinbuchstaben, Zahl, Sonderzeichen
- Sperrt häufig verwendete Passwörter (z.B. „123456", „passwort") und Benutzername/E-Mail-Name im Passwort
- Rollenbasiert: pro Rolle an- oder abschaltbar
- Administratoren sind **immer** verpflichtend eingeschlossen und lassen sich nicht ausschließen
- Prüft bei Profiländerung (eigenes Profil, Benutzer-Verwaltung, neue Benutzer), „Passwort vergessen"-Reset, Registrierung und WooCommerce „Mein Konto"
- Erzwingt bei Bestandsbenutzern betroffener Rollen eine Passwort-Änderung beim nächsten Login, da bereits gesetzte Passwörter nicht rückwirkend geprüft werden können
- Benutzer-Übersicht zeigt, wer noch ein neues Passwort setzen muss
- Automatische Update-Benachrichtigungen über GitHub

## Installation

1. [Neueste Version herunterladen](https://github.com/FreieGestalterischeRepublik/fgr-password-policy/archive/refs/heads/main.zip)
2. Im WordPress-Backend unter **Plugins → Installieren → Plugin hochladen** die ZIP-Datei hochladen
3. Plugin aktivieren
4. Unter **FGR Plugins → Password Policy** die Rollen und Kriterien konfigurieren

## Voraussetzungen

- WordPress 6.0 oder höher
- PHP 8.0 oder höher
