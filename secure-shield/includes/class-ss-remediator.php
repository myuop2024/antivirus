<?php
/**
 * Automatic repair and hardening routines.
 *
 * @package Secure_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Secure_Shield_Remediator {

    /**
     * Logger instance.
     *
     * @var Secure_Shield_Logger
     */
    protected $logger;

    /**
     * Settings handler.
     *
     * @var Secure_Shield_Settings
     */
    protected $settings;

    /**
     * Constructor.
     *
     * @param Secure_Shield_Logger   $logger    Logger instance.
     * @param Secure_Shield_Settings $settings  Settings handler.
     */
    public function __construct( Secure_Shield_Logger $logger, Secure_Shield_Settings $settings ) {
        $this->logger   = $logger;
        $this->settings = $settings;
    }

    /**
     * Register hooks.
     */
    public function register() {
        add_action( 'secure_shield/repair_core_file', array( $this, 'repair_core_file' ), 10, 1 );
    }

    /**
     * Attempt to repair a WordPress core file using trusted upstream sources.
     *
     * @param string $relative_path Relative path from the WordPress root.
     *
     * @return bool|WP_Error
     */
    public function repair_core_file( $relative_path ) {
        $relative_path = ltrim( $relative_path, '/' );
        $version       = get_bloginfo( 'version' );
        $candidates    = array(
            sprintf( 'https://raw.githubusercontent.com/WordPress/WordPress/%1$s/%2$s', $version, $relative_path ),
            sprintf( 'https://core.svn.wordpress.org/tags/%1$s/%2$s', $version, $relative_path ),
        );

        foreach ( $candidates as $candidate ) {
            $response = wp_remote_get( $candidate, array( 'timeout' => 20 ) );
            if ( is_wp_error( $response ) ) {
                do_action( 'secure_shield/log', sprintf( 'Auto-repair failed to fetch %1$s: %2$s', $candidate, $response->get_error_message() ), 'warning' );
                continue;
            }

            if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
                continue;
            }

            $contents = wp_remote_retrieve_body( $response );
            if ( empty( $contents ) ) {
                continue;
            }

            $destination = wp_normalize_path( ABSPATH . $relative_path );
            if ( ! wp_mkdir_p( dirname( $destination ) ) ) {
                return new WP_Error( 'repair_failed', __( 'Unable to create directories for repair.', 'secure-shield' ) );
            }

            if ( false === file_put_contents( $destination, $contents ) ) { // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.file_ops_file_put_contents
                continue;
            }

            do_action( 'secure_shield/log', sprintf( 'Repaired core file %s from %s', $relative_path, $candidate ), 'warning' );
            return true;
        }

        return new WP_Error( 'repair_failed', __( 'Unable to download trusted source for repair.', 'secure-shield' ) );
    }

    /**
     * Dispatch a repair request if auto-repair is enabled.
     *
     * @param string $relative_path Relative path from ABSPATH.
     *
     * @return bool|WP_Error
     */
    public function maybe_repair_core_file( $relative_path ) {
        if ( ! $this->settings->is_auto_repair_enabled() ) {
            return new WP_Error( 'auto_repair_disabled', __( 'Auto repair is disabled.', 'secure-shield' ) );
        }

        return $this->repair_core_file( $relative_path );
    }
}
