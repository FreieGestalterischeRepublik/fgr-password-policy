<?php
/**
 * Plugin Name:  FGR Password Policy
 * Description:  Erzwingt sichere Passwörter für ausgewählte Benutzerrollen. Administratoren sind immer verpflichtend eingeschlossen. Werbefrei.
 * Version:      1.0.2
 * Author:       Freie Gestalterische Republik
 * Author URI:   https://fgr.design
 * License:      GPL-2.0-or-later
 * Requires PHP: 7.4
 * Requires at least: 6.0
 * Text Domain:  fgr-password-policy
 */

defined( 'ABSPATH' ) || exit;

define( 'FGR_PP_VERSION', '1.0.2' );
define( 'FGR_PP_DIR',     plugin_dir_path( __FILE__ ) );
define( 'FGR_PP_URL',     plugin_dir_url( __FILE__ ) );

// Update-Checker: prüft GitHub auf neue Versionen
require_once FGR_PP_DIR . 'lib/plugin-update-checker/plugin-update-checker.php';
$fgr_pp_updater = YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
    'https://github.com/FreieGestalterischeRepublik/fgr-password-policy/',
    __FILE__,
    'fgr-password-policy'
);
$fgr_pp_updater->setBranch( 'main' );
$fgr_pp_updater->getVcsApi()->enableReleaseAssets();

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
