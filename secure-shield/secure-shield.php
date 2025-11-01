<?php
/**
 * Plugin Name: BISON Security Suite
 * Description: Advanced security suite providing malware scanning, vulnerability remediation, firewall hardening, AI-assisted remediations, and automated backups for WordPress.
 * Version: 1.1.0
 * Author: OpenAI Security Labs
 * License: GPL2
 * Text Domain: bison-security-suite
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! defined( 'SECURE_SHIELD_VERSION' ) ) {
    define( 'SECURE_SHIELD_VERSION', '1.1.0' );
}

if ( ! defined( 'SECURE_SHIELD_PATH' ) ) {
    define( 'SECURE_SHIELD_PATH', plugin_dir_path( __FILE__ ) );
}

if ( ! defined( 'SECURE_SHIELD_URL' ) ) {
    define( 'SECURE_SHIELD_URL', plugin_dir_url( __FILE__ ) );
}

if ( ! defined( 'SECURE_SHIELD_TEXT_DOMAIN' ) ) {
    define( 'SECURE_SHIELD_TEXT_DOMAIN', 'bison-security-suite' );
}

require_once SECURE_SHIELD_PATH . 'includes/class-ss-loader.php';

function secure_shield_run() {
    $plugin = new Secure_Shield_Loader();
    $plugin->run();
}

register_activation_hook( __FILE__, 'secure_shield_activate' );
register_deactivation_hook( __FILE__, 'secure_shield_deactivate' );

function secure_shield_activate() {
    secure_shield_run();
    if ( ! wp_next_scheduled( 'secure_shield_daily_scan' ) ) {
        wp_schedule_event( time(), 'secure_shield_6h', 'secure_shield_daily_scan' );
    }
    if ( ! wp_next_scheduled( 'secure_shield_hourly_maintenance' ) ) {
        wp_schedule_event( time(), 'hourly', 'secure_shield_hourly_maintenance' );
    }
    if ( ! wp_next_scheduled( 'secure_shield_update_signatures' ) ) {
        wp_schedule_event( time(), 'twicedaily', 'secure_shield_update_signatures' );
    }
    if ( '1' === get_option( 'secure_shield_realtime_updates', '1' ) && ! wp_next_scheduled( 'secure_shield_realtime_update' ) ) {
        wp_schedule_event( time(), 'secure_shield_5m', 'secure_shield_realtime_update' );
    }
}

function secure_shield_deactivate() {
    wp_clear_scheduled_hook( 'secure_shield_daily_scan' );
    wp_clear_scheduled_hook( 'secure_shield_hourly_maintenance' );
    wp_clear_scheduled_hook( 'secure_shield_update_signatures' );
    wp_clear_scheduled_hook( 'secure_shield_realtime_update' );
}

secure_shield_run();
