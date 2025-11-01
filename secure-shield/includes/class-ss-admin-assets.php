<?php
/**
 * Handles admin scripts and styles.
 *
 * @package Secure_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Secure_Shield_Admin_Assets {

    /**
     * Register hooks for enqueuing assets.
     */
    public function register() {
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
    }

    /**
     * Enqueue admin styles and scripts.
     *
     * @param string $hook Hook suffix.
     */
    public function enqueue_admin_assets( $hook ) {
        if ( false === strpos( $hook, 'secure-shield' ) ) {
            return;
        }

        wp_enqueue_style( 'secure-shield-admin', SECURE_SHIELD_URL . 'assets/css/admin.css', array(), SECURE_SHIELD_VERSION );
        wp_enqueue_script( 'secure-shield-admin', SECURE_SHIELD_URL . 'assets/js/admin.js', array( 'jquery', 'wp-util', 'wp-api-fetch' ), SECURE_SHIELD_VERSION, true );

        wp_localize_script(
            'secure-shield-admin',
            'secureShieldData',
            array(
                'nonce'      => wp_create_nonce( 'wp_rest' ),
                'restUrl'    => esc_url_raw( rest_url( 'secure-shield/v1' ) ),
                'scanStatus' => __( 'Scan in progress...', SECURE_SHIELD_TEXT_DOMAIN ),
                'labels'     => array(
                    'realtimeOn'  => __( 'Realtime Feeds Online', SECURE_SHIELD_TEXT_DOMAIN ),
                    'realtimeOff' => __( 'Realtime Feeds Paused', SECURE_SHIELD_TEXT_DOMAIN ),
                    'aiReady'     => __( 'AI Co-Pilot Ready', SECURE_SHIELD_TEXT_DOMAIN ),
                    'aiWaiting'   => __( 'Connect AI Co-Pilots', SECURE_SHIELD_TEXT_DOMAIN ),
                ),
            )
        );
    }
}
