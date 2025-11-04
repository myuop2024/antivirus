<?php
/**
 * Validates file and directory permissions.
 *
 * @package Secure_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Secure_Shield_Permissions {

    /**
     * Logger instance.
     *
     * @var Secure_Shield_Logger
     */
    protected $logger;

    /**
     * Constructor.
     *
     * @param Secure_Shield_Logger $logger Logger instance.
     */
    public function __construct( Secure_Shield_Logger $logger ) {
        $this->logger = $logger;
    }

    /**
     * Register admin hooks.
     */
    public function register() {
        add_action( 'secure_shield_check_permissions', array( $this, 'check_permissions' ) );
    }

    /**
     * Assess critical directories for improper permissions.
     *
     * @return array
     */
    public function check_permissions() {
        $paths = array(
            ABSPATH              => '0755',
            ABSPATH . 'wp-admin' => '0755',
            ABSPATH . 'wp-includes' => '0755',
            WP_CONTENT_DIR       => '0755',
            WP_CONTENT_DIR . '/uploads' => '0755',
            WP_CONTENT_DIR . '/plugins' => '0755',
            WP_CONTENT_DIR . '/themes'  => '0755',
            WP_CONTENT_DIR . '/secure-shield-quarantine' => '0700',
            ABSPATH . 'wp-config.php' => '0640',
            ABSPATH . '.htaccess'     => '0644',
        );

        $issues = array();
        foreach ( $paths as $path => $recommended ) {
            if ( ! file_exists( $path ) ) {
                continue;
            }

            $perms = substr( sprintf( '%o', fileperms( $path ) ), -4 );
            if ( $perms !== $recommended ) {
                $issues[ wp_normalize_path( $path ) ] = sprintf(
                    __( 'Permission %1$s detected, recommend %2$s.', 'secure-shield' ),
                    $perms,
                    $recommended
                );
            }
        }

        // Check for malicious .htaccess injections
        $this->check_htaccess_integrity( $issues );

        if ( ! empty( $issues ) ) {
            do_action( 'secure_shield/log', __( 'Permission issues detected.', 'secure-shield' ), 'warning' );
        }

        return $issues;
    }

    /**
     * Check .htaccess files for malicious content.
     *
     * @param array $issues Reference to issues array.
     */
    protected function check_htaccess_integrity( &$issues ) {
        $htaccess_locations = array(
            ABSPATH . '.htaccess',
            WP_CONTENT_DIR . '/.htaccess',
            WP_CONTENT_DIR . '/uploads/.htaccess',
        );

        $malicious_patterns = array(
            'auto_prepend_file' => __( 'Suspicious auto_prepend_file directive in .htaccess', 'secure-shield' ),
            'auto_append_file'  => __( 'Suspicious auto_append_file directive in .htaccess', 'secure-shield' ),
            'RewriteCond.*HTTP_USER_AGENT.*googlebot.*RewriteRule.*\[L,R=301\]' => __( 'SEO spam redirect detected in .htaccess', 'secure-shield' ),
            'base64'            => __( 'Base64 encoding detected in .htaccess', 'secure-shield' ),
            'eval\('            => __( 'Eval function in .htaccess', 'secure-shield' ),
            'RewriteRule.*\/tmp\/' => __( 'Suspicious tmp directory redirect in .htaccess', 'secure-shield' ),
            'RewriteRule.*\.(php|jpg|png).*\[L\].*http' => __( 'External redirect in .htaccess', 'secure-shield' ),
        );

        foreach ( $htaccess_locations as $htaccess_file ) {
            if ( ! file_exists( $htaccess_file ) ) {
                continue;
            }

            $content = @file_get_contents( $htaccess_file );
            if ( false === $content ) {
                continue;
            }

            foreach ( $malicious_patterns as $pattern => $description ) {
                if ( preg_match( '/' . $pattern . '/i', $content ) ) {
                    $relative_path = str_replace( ABSPATH, '', $htaccess_file );
                    $issues[ $relative_path ] = $description;
                }
            }
        }
    }
}
