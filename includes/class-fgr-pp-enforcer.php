<?php
defined( 'ABSPATH' ) || exit;

/**
 * Hängt die Passwort-Prüfung in alle relevanten WordPress-Abläufe ein und
 * erzwingt bei Bestandsbenutzern mit tatsächlich unsicherem Passwort eine
 * Änderung beim nächsten Login.
 *
 * Bereits gesetzte Passwort-Hashes können nicht direkt auf ihre Stärke
 * geprüft werden (WordPress speichert keine Klartext-Passwörter). Der
 * Klartext liegt aber kurz beim Login-Vorgang selbst vor (POST-Feld, bevor
 * WordPress ihn gegen den Hash prüft) – deshalb wird die Stärke dort per
 * "authenticate"-Filter geprüft und das "muss ändern"-Flag nur gesetzt,
 * wenn das Passwort die aktuellen Kriterien tatsächlich nicht erfüllt.
 */
class FGR_PP_Enforcer {

    const META_MUST_CHANGE = 'fgr_pp_must_change';

    public function __construct() {
        // Login: prüft das tatsächliche (Klartext-)Passwort gegen die Kriterien
        // und setzt/löscht das "muss ändern"-Flag danach. Priorität 30, damit
        // WordPress' eigene Passwort-Prüfung (Prio 20) bereits gelaufen ist.
        add_filter( 'authenticate', [ $this, 'check_password_on_login' ], 30, 3 );

        // Admin-Bereich: Profil bearbeiten (eigenes Profil, fremde Benutzer, neuer Benutzer)
        add_filter( 'user_profile_update_errors', [ $this, 'check_profile_update' ], 10, 3 );

        // Frontend: "Passwort vergessen"-Formular
        add_filter( 'validate_password_reset', [ $this, 'check_password_reset' ], 10, 2 );

        // Multisite- / Frontend-Registrierung mit eigenem Passwortfeld
        add_filter( 'registration_errors', [ $this, 'check_registration' ], 10, 3 );

        // WooCommerce "Mein Konto" (falls WooCommerce aktiv ist)
        add_filter( 'woocommerce_save_account_details_errors', [ $this, 'check_woocommerce_account' ], 10, 2 );

        // Flag löschen, sobald ein Benutzer sein Passwort erfolgreich geändert hat
        add_action( 'password_reset',  [ $this, 'clear_flag_after_reset' ], 10, 1 );
        add_action( 'profile_update',  [ $this, 'clear_flag_after_profile_update' ], 10, 1 );

        // Erzwungene Passwort-Änderung: Backend und Frontend
        add_action( 'admin_init',        [ $this, 'enforce_password_change' ] );
        add_action( 'template_redirect', [ $this, 'enforce_password_change' ] );
        add_action( 'admin_notices',     [ $this, 'render_requirement_notice' ] );

        // Rollen-Änderung in den Einstellungen: neu betroffene Bestandsbenutzer markieren
        add_action( 'fgr_pp_roles_changed', [ __CLASS__, 'handle_roles_changed' ], 10, 2 );
    }

    // =========================================================
    // Validierung an den verschiedenen Eintrittspunkten
    // =========================================================

    public function check_profile_update( WP_Error $errors, $update, $user ): void {
        if ( empty( $_POST['pass1'] ) ) return;

        // Aktuelle Rolle(n) des Benutzers als Basis (bei Eigenprofil ist im
        // Formular kein Rollenfeld vorhanden, dort greift dieser Fallback).
        $roles = [];
        if ( $update && ! empty( $user->ID ) ) {
            $existing = get_userdata( (int) $user->ID );
            $roles    = $existing ? $existing->roles : [];
        }

        // Bei Neuanlage oder Rollenänderung durch einen Admin hat die im
        // Formular gewählte Rolle Vorrang, da sie nach dem Speichern gilt.
        if ( ! empty( $_POST['role'] ) ) {
            $roles = [ sanitize_key( wp_unslash( $_POST['role'] ) ) ];
        }

        if ( ! FGR_PP_Validator::roles_require_policy( $roles ) ) return;

        $login = $user->user_login ?? '';
        $email = $user->user_email ?? '';

        foreach ( FGR_PP_Validator::check( wp_unslash( $_POST['pass1'] ), (string) $login, (string) $email ) as $msg ) {
            $errors->add( 'fgr_pp_weak_password', $msg );
        }
    }

    public function check_password_reset( WP_Error $errors, $user ): void {
        if ( is_wp_error( $user ) || empty( $_POST['pass1'] ) ) return;
        if ( ! FGR_PP_Validator::roles_require_policy( (array) $user->roles ) ) return;

        foreach ( FGR_PP_Validator::check( wp_unslash( $_POST['pass1'] ), $user->user_login, $user->user_email ) as $msg ) {
            $errors->add( 'fgr_pp_weak_password', $msg );
        }
    }

    public function check_registration( WP_Error $errors, $sanitized_user_login, $user_email ): void {
        if ( empty( $_POST['pass1'] ) ) return;
        // Neue Registrierungen bekommen i.d.R. die Standardrolle (meist Abonnent) –
        // nur relevant, wenn diese Rolle explizit in der Richtlinie enthalten ist.
        $default_role = get_option( 'default_role', 'subscriber' );
        if ( ! FGR_PP_Validator::roles_require_policy( [ $default_role ] ) ) return;

        foreach ( FGR_PP_Validator::check( wp_unslash( $_POST['pass1'] ), (string) $sanitized_user_login, (string) $user_email ) as $msg ) {
            $errors->add( 'fgr_pp_weak_password', $msg );
        }
    }

    public function check_woocommerce_account( WP_Error $errors, $user_param ): void {
        if ( empty( $_POST['password_1'] ) ) return;

        // WooCommerce reicht je nach Version entweder die User-ID oder das WP_User-Objekt durch.
        $user = ( $user_param instanceof WP_User ) ? $user_param : get_userdata( (int) $user_param );
        if ( ! $user || ! FGR_PP_Validator::roles_require_policy( (array) $user->roles ) ) return;

        foreach ( FGR_PP_Validator::check( wp_unslash( $_POST['password_1'] ), $user->user_login, $user->user_email ) as $msg ) {
            $errors->add( 'fgr_pp_weak_password', $msg );
        }
    }

    /**
     * Prüft beim Login das eingegebene Klartext-Passwort gegen die für die
     * Rolle(n) des Benutzers geltenden Kriterien. Nur bei tatsächlicher
     * Nichterfüllung wird das "muss ändern"-Flag gesetzt – ein bereits
     * konformes Passwort (auch ein "altes", vor der Richtlinie gesetztes)
     * bleibt unangetastet.
     */
    public function check_password_on_login( $user, $username, $password ) {
        if ( ! ( $user instanceof WP_User ) || empty( $password ) ) return $user;

        if ( ! FGR_PP_Validator::roles_require_policy( $user->roles ) ) {
            delete_user_meta( $user->ID, self::META_MUST_CHANGE );
            return $user;
        }

        $errors = FGR_PP_Validator::check( $password, $user->user_login, $user->user_email );
        if ( $errors ) {
            update_user_meta( $user->ID, self::META_MUST_CHANGE, 1 );
        } else {
            delete_user_meta( $user->ID, self::META_MUST_CHANGE );
        }

        return $user;
    }

    // =========================================================
    // Flag "muss Passwort ändern" verwalten
    // =========================================================

    public function clear_flag_after_reset( $user ): void {
        delete_user_meta( $user->ID, self::META_MUST_CHANGE );
    }

    public function clear_flag_after_profile_update( int $user_id ): void {
        if ( empty( $_POST['pass1'] ) ) return;
        delete_user_meta( $user_id, self::META_MUST_CHANGE );
    }

    /**
     * Wird eine Rolle aus der Richtlinie entfernt, entfällt für deren
     * Benutzer die Pflicht zur Passwort-Änderung (sofern keine ihrer
     * verbleibenden Rollen noch erfasst ist). Neu hinzugekommene Rollen
     * werden nicht mehr blind geflaggt – die Prüfung erfolgt stattdessen
     * automatisch beim nächsten Login (siehe check_password_on_login()).
     */
    public static function handle_roles_changed( array $old_roles, array $new_roles ): void {
        $removed = array_diff( $old_roles, $new_roles );
        if ( ! $removed ) return;

        $users = get_users( [ 'role__in' => $removed, 'fields' => 'ID' ] );
        foreach ( $users as $user_id ) {
            $user = get_userdata( $user_id );
            if ( $user && ! FGR_PP_Validator::roles_require_policy( $user->roles ) ) {
                delete_user_meta( $user_id, self::META_MUST_CHANGE );
            }
        }
    }

    // =========================================================
    // Erzwungene Passwort-Änderung beim nächsten Seitenaufruf
    // =========================================================

    public function enforce_password_change(): void {
        if ( ! is_user_logged_in() || wp_doing_ajax() ) return;

        $user = wp_get_current_user();
        if ( ! get_user_meta( $user->ID, self::META_MUST_CHANGE, true ) ) return;

        global $pagenow;
        if ( is_admin() && in_array( $pagenow, [ 'profile.php', 'user-edit.php', 'admin-ajax.php' ], true ) ) return;

        wp_safe_redirect( get_edit_profile_url( $user->ID ) . '#fgr-pp-required' );
        exit;
    }

    /**
     * Zeigt auf profile.php/user-edit.php einen Hinweis, wenn eine
     * Passwort-Änderung erforderlich ist.
     */
    public function render_requirement_notice(): void {
        global $pagenow;
        if ( ! in_array( $pagenow, [ 'profile.php', 'user-edit.php' ], true ) ) return;

        $user_id = ( 'user-edit.php' === $pagenow ) ? (int) ( $_GET['user_id'] ?? 0 ) : get_current_user_id();
        if ( ! $user_id || ! get_user_meta( $user_id, self::META_MUST_CHANGE, true ) ) return;
        ?>
        <div id="fgr-pp-required" class="notice notice-error">
            <p>
                <strong>Sicherheitsrichtlinie (FGR Password Policy):</strong>
                Für dieses Konto muss ein neues Passwort gesetzt werden, bevor es weiter genutzt werden kann.
                Anforderungen: <?php echo esc_html( FGR_PP_Validator::requirements_text() ); ?>.
            </p>
        </div>
        <?php
    }
}
