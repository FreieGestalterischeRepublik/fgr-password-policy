<?php
defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

// Plugin-Option löschen
delete_option( 'fgr_password_policy' );

// User-Meta aller Benutzer löschen
$users = get_users( [ 'fields' => 'ID', 'number' => -1 ] );
foreach ( $users as $user_id ) {
    delete_user_meta( $user_id, 'fgr_pp_must_change' );
}
