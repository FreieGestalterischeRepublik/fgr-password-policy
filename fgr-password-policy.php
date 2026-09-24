<?php
/**
 * Plugin Name:  FGR Password Policy
 * Description:  Erzwingt sichere Passwörter für ausgewählte Benutzerrollen. Administratoren sind immer verpflichtend eingeschlossen. Werbefrei.
 * Version:      1.0.3
 * Author:       Freie Gestalterische Republik
 * Author URI:   https://fgr.design
 * License:      GPL-2.0-or-later
 * Requires PHP: 7.4
 * Requires at least: 6.0
 * Text Domain:  fgr-password-policy
 */

defined( 'ABSPATH' ) || exit;

define( 'FGR_PP_VERSION', '1.0.3' );
define( 'FGR_PP_DIR',     plugin_dir_path( __FILE__ ) );
define( 'FGR_PP_URL',     plugin_dir_url( __FILE__ ) );

// Update-Checker: fragt die zentrale FGR-Update-API ab (nicht direkt GitHub)
require_once FGR_PP_DIR . 'lib/plugin-update-checker/plugin-update-checker.php';
$fgr_pp_updater = YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
    'https://fgr-plugins-api.fgr.design/fgr-password-policy.json',
    __FILE__,
    'fgr-password-policy'
);

// Auto-Update: WordPress' täglicher Update-Cron installiert neue Versionen
// dieses Plugins automatisch, kein manueller Klick auf jeder Seite nötig.
add_filter( 'auto_update_plugin', function ( $update, $item ) {
    if ( isset( $item->slug ) && $item->slug === 'fgr-password-policy' ) {
        return true;
    }
    return $update;
}, 10, 2 );

require_once FGR_PP_DIR . 'includes/class-fgr-pp-validator.php';
require_once FGR_PP_DIR . 'includes/class-fgr-pp-enforcer.php';
require_once FGR_PP_DIR . 'includes/class-fgr-pp-settings.php';

function fgr_pp_get_option(): array {
    $defaults = [
        'roles'            => [ 'administrator' ],
        'min_length'       => 12,
        'require_upper'    => true,
        'require_lower'    => true,
        'require_number'   => true,
        'require_special'  => true,
        'forbid_common'    => true,
        'forbid_username'  => true,
    ];
    return array_merge( $defaults, (array) get_option( 'fgr_password_policy', [] ) );
}

function fgr_pp_update_option( array $data ): void {
    update_option( 'fgr_password_policy', $data, false );
}

add_action( 'plugins_loaded', function () {
    new FGR_PP_Settings();
    new FGR_PP_Enforcer();
} );

// Kein pauschales Markieren bei Aktivierung mehr: Ob ein Passwort die
// Kriterien erfüllt, wird stattdessen beim nächsten Login anhand des dort
// kurz vorliegenden Klartext-Passworts geprüft (siehe FGR_PP_Enforcer).
