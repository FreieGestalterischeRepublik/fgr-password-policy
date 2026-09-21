<?php
defined( 'ABSPATH' ) || exit;

/**
 * Admin-Einstellungsseite: betroffene Rollen, Passwort-Kriterien, Benutzer-Übersicht.
 */
class FGR_PP_Settings {

    public function __construct() {
        add_action( 'admin_menu', [ $this, 'add_menu' ] );
        add_action( 'admin_init', [ $this, 'handle_save' ] );
    }

    public function add_menu(): void {
        add_submenu_page(
            'fgr-plugins',
            'FGR Password Policy',
            'Password Policy',
            'manage_options',
            'fgr-password-policy',
            [ $this, 'render_page' ]
        );
    }

    public function handle_save(): void {
        if ( ! isset( $_POST['fgr_pp_save'] ) ) return;
        if ( ! current_user_can( 'manage_options' ) ) return;
        check_admin_referer( 'fgr_pp_save', 'fgr_pp_nonce' );

        $old_opt   = fgr_pp_get_option();
        $old_roles = $old_opt['roles'];

        $roles = array_map( 'sanitize_key', (array) ( $_POST['roles'] ?? [] ) );
        global $wp_roles;
        $valid = array_keys( $wp_roles->get_names() );
        $roles = array_values( array_intersect( $roles, $valid ) );

        // Administratoren sind niemals ausschließbar.
        if ( ! in_array( 'administrator', $roles, true ) ) {
            $roles[] = 'administrator';
        }

        $new_opt = [
            'roles'           => $roles,
            'min_length'      => max( 4, min( 64, (int) ( $_POST['min_length'] ?? 12 ) ) ),
            'require_upper'   => ! empty( $_POST['require_upper'] ),
            'require_lower'   => ! empty( $_POST['require_lower'] ),
            'require_number'  => ! empty( $_POST['require_number'] ),
            'require_special' => ! empty( $_POST['require_special'] ),
            'forbid_common'   => ! empty( $_POST['forbid_common'] ),
            'forbid_username' => ! empty( $_POST['forbid_username'] ),
        ];

        fgr_pp_update_option( $new_opt );

        if ( array_diff( $roles, $old_roles ) || array_diff( $old_roles, $roles ) ) {
            do_action( 'fgr_pp_roles_changed', $old_roles, $roles );
        }

        add_settings_error( 'fgr_pp', 'saved', 'Einstellungen gespeichert.', 'success' );
    }

    public function render_page(): void {
        if ( ! current_user_can( 'manage_options' ) ) return;
        settings_errors( 'fgr_pp' );

        $opt   = fgr_pp_get_option();
        $roles = $opt['roles'];

        global $wp_roles;
        $all_roles = $wp_roles->get_names();
        ?>
        <div class="wrap">
            <h1>FGR Password Policy</h1>
            <p style="color:#888;margin-top:-8px">aus der <em>Freien Gestalterischen Republik</em></p>

            <form method="post">
                <?php wp_nonce_field( 'fgr_pp_save', 'fgr_pp_nonce' ); ?>

                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row">Sichere Passwörter erforderlich für</th>
                        <td>
                            <?php foreach ( $all_roles as $slug => $name ) :
                                $is_admin_role = ( 'administrator' === $slug );
                            ?>
                            <label style="display:block;margin-bottom:6px">
                                <input type="checkbox" name="roles[]"
                                       value="<?php echo esc_attr( $slug ); ?>"
                                       <?php checked( in_array( $slug, $roles, true ) || $is_admin_role ); ?>
                                       <?php disabled( $is_admin_role ); ?>>
                                <?php echo esc_html( translate_user_role( $name ) ); ?>
                                <?php if ( $is_admin_role ) : ?>
                                    <span style="color:#888">(immer verpflichtend)</span>
                                <?php endif; ?>
                            </label>
                            <?php if ( $is_admin_role ) : ?>
                                <input type="hidden" name="roles[]" value="administrator">
                            <?php endif; ?>
                            <?php endforeach; ?>
                            <p class="description">
                                Für Benutzer dieser Rollen wird beim Setzen eines Passworts geprüft,
                                ob es die untenstehenden Kriterien erfüllt. Administratoren können
                                nicht ausgeschlossen werden.
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Mindestlänge</th>
                        <td>
                            <input type="number" name="min_length" min="4" max="64"
                                   value="<?php echo esc_attr( $opt['min_length'] ); ?>" style="width:80px">
                            Zeichen
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Kriterien</th>
                        <td>
                            <label style="display:block;margin-bottom:6px">
                                <input type="checkbox" name="require_upper" value="1" <?php checked( $opt['require_upper'] ); ?>>
                                Mindestens ein Großbuchstabe
                            </label>
                            <label style="display:block;margin-bottom:6px">
                                <input type="checkbox" name="require_lower" value="1" <?php checked( $opt['require_lower'] ); ?>>
                                Mindestens ein Kleinbuchstabe
                            </label>
                            <label style="display:block;margin-bottom:6px">
                                <input type="checkbox" name="require_number" value="1" <?php checked( $opt['require_number'] ); ?>>
                                Mindestens eine Zahl
                            </label>
                            <label style="display:block;margin-bottom:6px">
                                <input type="checkbox" name="require_special" value="1" <?php checked( $opt['require_special'] ); ?>>
                                Mindestens ein Sonderzeichen
                            </label>
                            <label style="display:block;margin-bottom:6px">
                                <input type="checkbox" name="forbid_common" value="1" <?php checked( $opt['forbid_common'] ); ?>>
                                Häufig verwendete Passwörter verbieten (z.B. „123456", „passwort")
                            </label>
                            <label style="display:block;margin-bottom:6px">
                                <input type="checkbox" name="forbid_username" value="1" <?php checked( $opt['forbid_username'] ); ?>>
                                Benutzername/E-Mail-Name darf nicht im Passwort vorkommen
                            </label>
                        </td>
                    </tr>
                </table>

                <p class="submit">
                    <button type="submit" name="fgr_pp_save" class="button button-primary">
                        Einstellungen speichern
                    </button>
                </p>
            </form>

            <hr>
            <h2>Benutzer-Übersicht</h2>
            <p class="description">
                Da WordPress Passwörter nur verschlüsselt speichert, kann die Stärke bereits
                gesetzter Passwörter nicht rückwirkend geprüft werden. Wird eine Rolle neu in
                die Richtlinie aufgenommen, müssen deren Benutzer beim nächsten Login ein neues,
                konformes Passwort setzen.
            </p>
            <?php $this->render_user_table(); ?>
        </div>
        <?php
    }

    private function render_user_table(): void {
        $users = get_users( [ 'number' => 200, 'orderby' => 'login' ] );
        ?>
        <table class="wp-list-table widefat fixed striped" style="max-width:700px">
            <thead>
                <tr>
                    <th>Benutzer</th>
                    <th>Rolle</th>
                    <th>Passwort-Status</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ( $users as $user ) :
                    $must_change = (bool) get_user_meta( $user->ID, FGR_PP_Enforcer::META_MUST_CHANGE, true );
                ?>
                <tr>
                    <td><strong><?php echo esc_html( $user->user_login ); ?></strong></td>
                    <td><?php echo esc_html( implode( ', ', $user->roles ) ); ?></td>
                    <td>
                        <?php if ( $must_change ) : ?>
                            <span style="color:#dc3545">✗ Änderung beim nächsten Login erforderlich</span>
                        <?php else : ?>
                            <span style="color:green">✓ Konform</span>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <?php
    }
}
