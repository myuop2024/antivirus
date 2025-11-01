<?php
/**
 * Handles automatic plugin updates and threat intel sync.
 *
 * @package Secure_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Secure_Shield_Updater {

    /**
     * Signature manager.
     *
     * @var Secure_Shield_Signature_Manager
     */
    protected $signature_manager;

    /**
     * Logger instance.
     *
     * @var Secure_Shield_Logger
     */
    protected $logger;

    /**
     * Constructor.
     *
     * @param Secure_Shield_Signature_Manager $signature_manager Signatures.
     * @param Secure_Shield_Logger            $logger Logger.
     */
    public function __construct( Secure_Shield_Signature_Manager $signature_manager, Secure_Shield_Logger $logger ) {
        $this->signature_manager = $signature_manager;
        $this->logger            = $logger;
    }

    /**
     * Register updater hooks.
     */
    public function register() {
        add_filter( 'auto_update_plugin', array( $this, 'force_auto_update' ), 10, 2 );
        add_action( 'upgrader_process_complete', array( $this, 'after_plugin_update' ), 10, 2 );
    }

    /**
     * Force auto-update for BISON Security Suite plugin.
     *
     * @param bool   $update Should update.
     * @param object $item   Update item.
     *
     * @return bool
     */
    public function force_auto_update( $update, $item ) {
        if ( isset( $item->slug ) && 'secure-shield' === $item->slug ) {
            return true;
        }
        return $update;
    }

    /**
     * After plugin update, refresh signatures.
     *
     * @param WP_Upgrader $upgrader Upgrader.
     * @param array       $options Options.
     */
    public function after_plugin_update( $upgrader, $options ) {
        if ( 'update' === $options['action'] && 'plugin' === $options['type'] ) {
            $plugins = $options['plugins'] ?? array();
            foreach ( $plugins as $plugin ) {
                if ( false !== strpos( $plugin, 'secure-shield.php' ) ) {
                    $this->signature_manager->update_signatures();
                    do_action( 'secure_shield/log', __( 'BISON Security Suite updated and signatures refreshed.', SECURE_SHIELD_TEXT_DOMAIN ) );
                }
            }
        }
    }
}
