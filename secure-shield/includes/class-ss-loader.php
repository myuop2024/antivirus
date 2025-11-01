<?php
/**
 * Main loader for Secure Shield Security Suite.
 *
 * @package Secure_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Secure_Shield_Loader {

    /**
     * Registered services container.
     *
     * @var array
     */
    protected $services = array();

    /**
     * Run the plugin bootstrap.
     */
    public function run() {
        $this->load_dependencies();
        $this->register_services();
    }

    /**
     * Load plugin dependencies.
     */
    protected function load_dependencies() {
        require_once SECURE_SHIELD_PATH . 'includes/class-ss-logger.php';
        require_once SECURE_SHIELD_PATH . 'includes/class-ss-admin-assets.php';
        require_once SECURE_SHIELD_PATH . 'includes/class-ss-settings.php';
        require_once SECURE_SHIELD_PATH . 'includes/class-ss-remediator.php';
        require_once SECURE_SHIELD_PATH . 'includes/class-ss-scanner.php';
        require_once SECURE_SHIELD_PATH . 'includes/class-ss-signature-manager.php';
        require_once SECURE_SHIELD_PATH . 'includes/class-ss-permissions.php';
        require_once SECURE_SHIELD_PATH . 'includes/class-ss-firewall.php';
        require_once SECURE_SHIELD_PATH . 'includes/class-ss-cloudflare.php';
        require_once SECURE_SHIELD_PATH . 'includes/class-ss-scheduler.php';
        require_once SECURE_SHIELD_PATH . 'includes/class-ss-rest.php';
        require_once SECURE_SHIELD_PATH . 'includes/class-ss-updater.php';
        require_once SECURE_SHIELD_PATH . 'includes/class-ss-backup.php';
        require_once SECURE_SHIELD_PATH . 'includes/class-ss-dashboard.php';
    }

    /**
     * Register plugin services.
     */
    protected function register_services() {
        $this->services['logger']      = new Secure_Shield_Logger();
        $this->services['settings']    = new Secure_Shield_Settings( $this->services['logger'] );
        $this->services['remediator']  = new Secure_Shield_Remediator( $this->services['logger'], $this->services['settings'] );
        $this->services['signatures']  = new Secure_Shield_Signature_Manager( $this->services['logger'], $this->services['settings'] );
        $this->services['scanner']     = new Secure_Shield_Scanner( $this->services['logger'], $this->services['signatures'], $this->services['settings'], $this->services['remediator'] );
        $this->services['permissions'] = new Secure_Shield_Permissions( $this->services['logger'] );
        $this->services['firewall']    = new Secure_Shield_Firewall( $this->services['logger'] );
        $this->services['cloudflare']  = new Secure_Shield_Cloudflare( $this->services['logger'] );
        $this->services['scheduler']   = new Secure_Shield_Scheduler( $this->services['scanner'], $this->services['permissions'], $this->services['firewall'], $this->services['logger'] );
        $this->services['backup']      = new Secure_Shield_Backup( $this->services['logger'] );
        $this->services['dashboard']   = new Secure_Shield_Dashboard( $this->services['scanner'], $this->services['permissions'], $this->services['firewall'], $this->services['cloudflare'], $this->services['scheduler'], $this->services['backup'], $this->services['logger'], $this->services['settings'] );
        $this->services['rest']       = new Secure_Shield_REST( $this->services['scanner'], $this->services['logger'] );
        $this->services['assets']     = new Secure_Shield_Admin_Assets();
        $this->services['updater']    = new Secure_Shield_Updater( $this->services['signatures'], $this->services['logger'] );

        add_action( 'secure_shield/firewall_block', array( $this->services['cloudflare'], 'block_ip' ), 10, 1 );
        add_action( 'plugins_loaded', array( $this, 'load_textdomain' ) );

        foreach ( $this->services as $service ) {
            if ( method_exists( $service, 'register' ) ) {
                $service->register();
            }
        }
    }

    /**
     * Load plugin textdomain for translations.
     */
    public function load_textdomain() {
        load_plugin_textdomain( 'secure-shield', false, dirname( plugin_basename( SECURE_SHIELD_PATH . 'secure-shield.php' ) ) . '/languages' );
    }
}
