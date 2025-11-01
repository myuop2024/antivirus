<?php
/**
 * Admin dashboard UI for BISON Security Suite.
 *
 * @package Secure_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Secure_Shield_Dashboard {

    protected $scanner;
    protected $permissions;
    protected $firewall;
    protected $cloudflare;
    protected $scheduler;
    protected $backup;
    protected $logger;
    protected $settings;

    public function __construct( Secure_Shield_Scanner $scanner, Secure_Shield_Permissions $permissions, Secure_Shield_Firewall $firewall, Secure_Shield_Cloudflare $cloudflare, Secure_Shield_Scheduler $scheduler, Secure_Shield_Backup $backup, Secure_Shield_Logger $logger, Secure_Shield_Settings $settings ) {
        $this->scanner     = $scanner;
        $this->permissions = $permissions;
        $this->firewall    = $firewall;
        $this->cloudflare  = $cloudflare;
        $this->scheduler   = $scheduler;
        $this->backup      = $backup;
        $this->logger      = $logger;
        $this->settings    = $settings;
    }

    public function register() {
        add_action( 'admin_menu', array( $this, 'register_menu' ) );
        add_action( 'admin_post_secure_shield_scan', array( $this, 'handle_scan_action' ) );
        add_action( 'admin_post_secure_shield_backup', array( $this, 'handle_backup_action' ) );
        add_action( 'admin_post_secure_shield_restore', array( $this, 'handle_restore_action' ) );
    }

    public function register_menu() {
        add_menu_page(
            __( 'BISON Security Suite', SECURE_SHIELD_TEXT_DOMAIN ),
            __( 'BISON Security Suite', SECURE_SHIELD_TEXT_DOMAIN ),
            'manage_options',
            'secure-shield',
            array( $this, 'render_dashboard' ),
            'dashicons-shield-alt',
            2
        );

        add_submenu_page(
            'secure-shield',
            __( 'Threat Logs', SECURE_SHIELD_TEXT_DOMAIN ),
            __( 'Threat Logs', SECURE_SHIELD_TEXT_DOMAIN ),
            'manage_options',
            'secure-shield-logs',
            array( $this, 'render_logs' )
        );
    }

    public function render_dashboard() {
        $results      = get_option( Secure_Shield_Scanner::OPTION_SCAN_RESULTS, array() );
        $permissions  = get_option( 'secure_shield_permission_issues', array() );
        $blocklist    = $this->firewall->get_blocklist();
        $backups      = $this->backup->list_backups();
        $signatures   = get_option( Secure_Shield_Signature_Manager::OPTION_SIGNATURES, array() );
        $last_update  = get_option( Secure_Shield_Signature_Manager::OPTION_LAST_UPDATE, 0 );
        $settings     = $this->settings;
        $theme_scans  = get_option( 'secure_shield_theme_scan_history', array() );

        include SECURE_SHIELD_PATH . 'templates/dashboard.php';
    }

    public function render_logs() {
        $logs = $this->logger->get_logs();
        include SECURE_SHIELD_PATH . 'templates/logs.php';
    }

    public function handle_scan_action() {
        check_admin_referer( 'secure_shield_scan' );
        $type = isset( $_POST['scan_type'] ) ? sanitize_text_field( wp_unslash( $_POST['scan_type'] ) ) : 'quick';
        $results = $this->scanner->scan( $type );
        update_option( Secure_Shield_Scanner::OPTION_SCAN_RESULTS, $results, false );
        wp_safe_redirect( add_query_arg( 'message', 'scan_complete', wp_get_referer() ) );
        exit;
    }

    public function handle_backup_action() {
        check_admin_referer( 'secure_shield_backup' );
        $backup = $this->backup->create_backup();
        if ( is_wp_error( $backup ) ) {
            wp_safe_redirect( add_query_arg( 'message', 'backup_failed', wp_get_referer() ) );
        } else {
            wp_safe_redirect( add_query_arg( 'message', 'backup_success', wp_get_referer() ) );
        }
        exit;
    }

    public function handle_restore_action() {
        check_admin_referer( 'secure_shield_restore' );
        $file = isset( $_POST['backup_file'] ) ? sanitize_text_field( wp_unslash( $_POST['backup_file'] ) ) : '';
        $result = $this->backup->restore_backup( $file );
        if ( is_wp_error( $result ) ) {
            wp_safe_redirect( add_query_arg( 'message', 'restore_failed', wp_get_referer() ) );
        } else {
            wp_safe_redirect( add_query_arg( 'message', 'restore_success', wp_get_referer() ) );
        }
        exit;
    }
}
