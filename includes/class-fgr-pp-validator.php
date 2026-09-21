<?php
defined( 'ABSPATH' ) || exit;

require_once __DIR__ . '/common-passwords.php';

/**
 * Prüft ein Passwort gegen die konfigurierten Kriterien.
 */
class FGR_PP_Validator {

    /**
     * Gibt eine Liste von Fehlermeldungen zurück (leer = Passwort ok).
     *
     * @param string       $password Klartext-Passwort.
     * @param string       $login    Benutzername (für "Benutzername im Passwort"-Prüfung).
     * @param string       $email    E-Mail-Adresse (dito).
     */
    public static function check( string $password, string $login = '', string $email = '' ): array {
        $opt    = fgr_pp_get_option();
        $errors = [];

        $min_length = max( 1, (int) $opt['min_length'] );
        if ( strlen( $password ) < $min_length ) {
            $errors[] = sprintf( 'Das Passwort muss mindestens %d Zeichen lang sein.', $min_length );
        }

        if ( ! empty( $opt['require_upper'] ) && ! preg_match( '/[A-ZÄÖÜ]/', $password ) ) {
            $errors[] = 'Das Passwort muss mindestens einen Großbuchstaben enthalten.';
        }

        if ( ! empty( $opt['require_lower'] ) && ! preg_match( '/[a-zäöüß]/', $password ) ) {
            $errors[] = 'Das Passwort muss mindestens einen Kleinbuchstaben enthalten.';
        }

        if ( ! empty( $opt['require_number'] ) && ! preg_match( '/[0-9]/', $password ) ) {
            $errors[] = 'Das Passwort muss mindestens eine Zahl enthalten.';
        }

        if ( ! empty( $opt['require_special'] ) && ! preg_match( '/[^A-Za-z0-9ÄÖÜäöüß]/', $password ) ) {
            $errors[] = 'Das Passwort muss mindestens ein Sonderzeichen enthalten (z.B. ! ? # % &).';
        }

        if ( ! empty( $opt['forbid_common'] ) && in_array( strtolower( $password ), fgr_pp_common_passwords(), true ) ) {
            $errors[] = 'Dieses Passwort ist zu leicht zu erraten. Bitte ein individuelleres Passwort wählen.';
        }

        if ( ! empty( $opt['forbid_username'] ) ) {
            $needle_login = strtolower( trim( $login ) );
            $needle_mail  = strtolower( trim( strtok( (string) $email, '@' ) ) );
            $haystack     = strtolower( $password );

            if ( ( $needle_login && strlen( $needle_login ) >= 3 && str_contains( $haystack, $needle_login ) )
                || ( $needle_mail && strlen( $needle_mail ) >= 3 && str_contains( $haystack, $needle_mail ) ) ) {
                $errors[] = 'Das Passwort darf nicht den Benutzernamen oder Teile der E-Mail-Adresse enthalten.';
            }
        }

        return $errors;
    }

    /**
     * Prüft, ob die übergebenen Rollen von der Passwort-Richtlinie betroffen sind.
     */
    public static function roles_require_policy( array $user_roles ): bool {
        $opt = fgr_pp_get_option();
        return (bool) array_intersect( $user_roles, $opt['roles'] );
    }

    /**
     * Menschenlesbare Zusammenfassung der aktuell aktiven Kriterien (für Hinweistexte).
     */
    public static function requirements_text(): string {
        $opt   = fgr_pp_get_option();
        $parts = [ sprintf( 'mindestens %d Zeichen', max( 1, (int) $opt['min_length'] ) ) ];

        if ( ! empty( $opt['require_upper'] ) )   $parts[] = 'Großbuchstabe';
        if ( ! empty( $opt['require_lower'] ) )   $parts[] = 'Kleinbuchstabe';
        if ( ! empty( $opt['require_number'] ) )  $parts[] = 'Zahl';
        if ( ! empty( $opt['require_special'] ) ) $parts[] = 'Sonderzeichen';

        return implode( ', ', $parts );
    }
}
