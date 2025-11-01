<?php
/**
 * File and database scanner.
 *
 * @package Secure_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Secure_Shield_Scanner {

    const OPTION_SCAN_RESULTS = 'secure_shield_scan_results';

    /**
     * Logger instance.
     *
     * @var Secure_Shield_Logger
     */
    protected $logger;

    /**
     * Signature manager.
     *
     * @var Secure_Shield_Signature_Manager
     */
    protected $signature_manager;

    /**
     * Settings handler.
     *
     * @var Secure_Shield_Settings
     */
    protected $settings;

    /**
     * Remediation helper.
     *
     * @var Secure_Shield_Remediator
     */
    protected $remediator;

    /**
     * Constructor.
     *
     * @param Secure_Shield_Logger            $logger Logger instance.
     * @param Secure_Shield_Signature_Manager $signature_manager Signatures.
     * @param Secure_Shield_Settings          $settings Settings handler.
     * @param Secure_Shield_Remediator        $remediator Remediation helper.
     */
    public function __construct( Secure_Shield_Logger $logger, Secure_Shield_Signature_Manager $signature_manager, ?Secure_Shield_Settings $settings = null, ?Secure_Shield_Remediator $remediator = null ) {
        $this->logger            = $logger;
        $this->signature_manager = $signature_manager;
        $this->settings          = $settings;
        $this->remediator        = $remediator;
    }

    /**
     * Register REST and cron actions.
     */
    public function register() {
        add_action( 'secure_shield_run_scan', array( $this, 'run_scheduled_scan' ), 10, 2 );
        add_action( 'secure_shield_clean_item', array( $this, 'clean_item' ), 10, 2 );
        add_action( 'upgrader_process_complete', array( $this, 'scan_new_install' ), 20, 2 );
    }

    /**
     * Run a scheduled scan.
     *
     * @param string $scan_type  Scan type.
     * @param array  $scan_paths Paths to scan.
     */
    public function run_scheduled_scan( $scan_type = 'quick', $scan_paths = array() ) {
        $results = $this->scan( $scan_type, $scan_paths );
        update_option( self::OPTION_SCAN_RESULTS, $results, false );

        if ( ! empty( $results['critical'] ) ) {
            $this->notify_admin( $results );
        }
    }

    /**
     * Execute a manual scan.
     *
     * @param string $scan_type Scan type.
     * @param array  $scan_paths Paths to scan.
     *
     * @return array
     */
    public function scan( $scan_type = 'quick', $scan_paths = array() ) {
        $signatures = $this->signature_manager->get_signatures();
        $results    = array(
            'scan_type' => $scan_type,
            'start'     => current_time( 'timestamp' ),
            'files'     => array(),
            'database'  => array(),
            'critical'  => array(),
            'warnings'  => array(),
            'info'      => array(),
            'integrity' => array(
                'core'    => array(),
                'plugins' => array(),
                'themes'  => array(),
            ),
            'ai_guidance' => array(),
            'quarantined' => array(),
        );

        $paths = $this->determine_paths( $scan_type, $scan_paths );

        foreach ( $paths as $path ) {
            if ( is_dir( $path ) ) {
                $iterator = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $path, RecursiveDirectoryIterator::SKIP_DOTS ) );
                foreach ( $iterator as $file ) {
                    $file_path = $file->getPathname();
                    $this->inspect_file( $file_path, $signatures, $results );
                }
            } elseif ( file_exists( $path ) ) {
                $this->inspect_file( $path, $signatures, $results );
            }
        }

        $this->inspect_database( $signatures, $results );
        $this->verify_integrity( $results );

        $results['end'] = current_time( 'timestamp' );
        do_action( 'secure_shield/log', sprintf( 'Scan completed with %d critical issues.', count( $results['critical'] ) ) );
        return $results;
    }

    /**
     * Determine directories to scan by type.
     *
     * @param string $scan_type Scan type.
     * @param array  $scan_paths Custom paths.
     *
     * @return array
     */
    protected function determine_paths( $scan_type, $scan_paths ) {
        if ( ! empty( $scan_paths ) ) {
            return array_map( 'wp_normalize_path', $scan_paths );
        }

        $root = wp_normalize_path( ABSPATH );
        $paths = array( $root . 'wp-admin', $root . 'wp-includes', WP_CONTENT_DIR );

        if ( 'deep' === $scan_type ) {
            $paths[] = $root;
        } elseif ( 'core' === $scan_type ) {
            $paths = array( $root . 'wp-admin', $root . 'wp-includes' );
        }

        return array_unique( array_filter( $paths ) );
    }

    /**
     * Inspect file contents against signatures.
     *
     * @param string $file_path File path.
     * @param array  $signatures Signatures.
     * @param array  $results Results reference.
     */
    protected function inspect_file( $file_path, $signatures, &$results ) {
        $ext = strtolower( pathinfo( $file_path, PATHINFO_EXTENSION ) );
        $relevant_extensions = array( 'php', 'js', 'html', 'htm', 'phtml' );

        if ( ! in_array( $ext, $relevant_extensions, true ) ) {
            return;
        }

        $contents = @file_get_contents( $file_path );
        if ( false === $contents ) {
            return;
        }

        $file_relative = str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $file_path ) );
        foreach ( $signatures as $signature => $description ) {
            if ( stripos( $contents, $signature ) !== false ) {
                $results['files'][ $file_relative ][] = array(
                    'signature'   => $signature,
                    'description' => $description,
                    'severity'    => $this->determine_severity( $signature ),
                );
                $severity = $this->determine_severity( $signature );
                if ( 'critical' === $severity ) {
                    $results['critical'][ $file_relative ] = $description;
                    if ( $this->remediator && empty( $results['ai_guidance'][ $file_relative ] ) ) {
                        $guidance = $this->remediator->generate_ai_guidance(
                            $file_path,
                            array(
                                'signature'   => $signature,
                                'description' => $description,
                                'snippet'     => $this->extract_snippet( $contents, $signature ),
                            )
                        );
                        if ( ! empty( $guidance ) ) {
                            $results['ai_guidance'][ $file_relative ] = $guidance;
                        }
                    }
                }
            }
        }

        $checksum = md5( $contents );
        $stored   = get_site_option( 'secure_shield_checksums', array() );
        if ( isset( $stored[ $file_relative ] ) && $stored[ $file_relative ] !== $checksum ) {
            $results['warnings'][ $file_relative ] = __( 'File integrity mismatch detected.', SECURE_SHIELD_TEXT_DOMAIN );
        }
        $stored[ $file_relative ] = $checksum;
        update_site_option( 'secure_shield_checksums', $stored );
    }

    /**
     * Extract a snippet around the signature match.
     *
     * @param string $contents File contents.
     * @param string $signature Signature string.
     *
     * @return string
     */
    protected function extract_snippet( $contents, $signature ) {
        $position = stripos( $contents, $signature );
        if ( false === $position ) {
            return substr( $contents, 0, 400 );
        }

        $start = max( 0, $position - 200 );
        $snippet = substr( $contents, $start, strlen( $signature ) + 400 );

        return trim( $snippet );
    }

    /**
     * Verify WordPress core checksums against official sources.
     *
     * @param array $results Results reference.
     */
    protected function verify_integrity( &$results ) {
        $version = get_bloginfo( 'version' );
        $locale  = function_exists( 'determine_locale' ) ? determine_locale() : get_locale();

        $response = wp_remote_get(
            add_query_arg(
                array(
                    'version' => rawurlencode( $version ),
                    'locale'  => rawurlencode( $locale ),
                ),
                'https://api.wordpress.org/core/checksums/1.0/'
            ),
            array( 'timeout' => 20 )
        );

        if ( is_wp_error( $response ) ) {
            do_action( 'secure_shield/log', sprintf( 'Integrity check failed: %s', $response->get_error_message() ), 'warning' );
            return;
        }

        $data = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( empty( $data['checksums'] ) || ! is_array( $data['checksums'] ) ) {
            return;
        }

        foreach ( $data['checksums'] as $file => $checksum ) {
            $full_path = wp_normalize_path( ABSPATH . $file );
            if ( ! file_exists( $full_path ) ) {
                $results['integrity']['core'][ $file ] = __( 'Core file missing from installation.', SECURE_SHIELD_TEXT_DOMAIN );
                $results['critical'][ 'core:' . $file ] = __( 'Core file missing from installation.', SECURE_SHIELD_TEXT_DOMAIN );
                continue;
            }

            $contents = @file_get_contents( $full_path );
            if ( false === $contents ) {
                continue;
            }

            $hash = md5( $contents );
            if ( strtolower( $hash ) !== strtolower( $checksum ) ) {
                $results['integrity']['core'][ $file ] = __( 'Core file integrity mismatch detected.', SECURE_SHIELD_TEXT_DOMAIN );
                $results['critical'][ 'core:' . $file ] = __( 'Core file integrity mismatch detected.', SECURE_SHIELD_TEXT_DOMAIN );

                if ( $this->settings && $this->settings->is_auto_repair_enabled() && $this->remediator ) {
                    $repair = $this->remediator->maybe_repair_core_file( $file );
                    if ( is_wp_error( $repair ) ) {
                        $results['warnings'][ 'core:' . $file ] = $repair->get_error_message();
                    } else {
                        $results['info'][ 'core:' . $file ] = __( 'Core file automatically repaired using trusted source.', SECURE_SHIELD_TEXT_DOMAIN );
                    }
                }
            }
        }
    }

    /**
     * Inspect posts and comments for malicious payloads.
     *
     * @param array $signatures Signatures.
     * @param array $results Results reference.
     */
    protected function inspect_database( $signatures, &$results ) {
        global $wpdb;

        $targets = array(
            'posts'    => array(
                'table' => $wpdb->posts,
                'id'    => 'ID',
                'field' => 'post_content',
            ),
            'comments' => array(
                'table' => $wpdb->comments,
                'id'    => 'comment_ID',
                'field' => 'comment_content',
            ),
        );

        foreach ( $targets as $type => $meta ) {
            $id_field    = $meta['id'];
            $content_key = $meta['field'];
            $table       = $meta['table'];
            $rows        = $wpdb->get_results( "SELECT {$id_field} as id, {$content_key} as content FROM {$table} ORDER BY {$id_field} DESC LIMIT 500", ARRAY_A );
            foreach ( (array) $rows as $row ) {
                $content = $row['content'] ?? '';
                foreach ( $signatures as $signature => $description ) {
                    if ( stripos( $content, $signature ) !== false ) {
                        $key = $type . ':' . $row['id'];
                        $results['database'][ $key ][] = array(
                            'signature'   => $signature,
                            'description' => $description,
                            'severity'    => $this->determine_severity( $signature ),
                        );
                        if ( 'critical' === $this->determine_severity( $signature ) ) {
                            $results['critical'][ $key ] = $description;
                        }
                    }
                }
            }
        }
    }

    /**
     * Determine severity for a given signature.
     *
     * @param string $signature Signature string.
     *
     * @return string
     */
    protected function determine_severity( $signature ) {
        $critical = array( 'eval(', 'shell_exec(', 'passthru(', 'base64_decode(' );
        foreach ( $critical as $match ) {
            if ( false !== strpos( $signature, $match ) ) {
                return 'critical';
            }
        }
        return 'warning';
    }

    /**
     * Cleanup suspicious item.
     *
     * @param string $type Item type.
     * @param string $identifier Identifier.
     */
    public function clean_item( $type, $identifier ) {
        $type = sanitize_key( $type );
        $identifier = sanitize_text_field( $identifier );

        if ( 'file' === $type ) {
            if ( $this->remediator ) {
                $this->remediator->quarantine_file( $identifier );
            }
        }

        if ( 'database' === $type ) {
            list( $scope, $id ) = array_pad( explode( ':', $identifier ), 2, null );
            global $wpdb;
            if ( 'posts' === $scope ) {
                $wpdb->update( $wpdb->posts, array( 'post_content' => '' ), array( 'ID' => absint( $id ) ) );
            } elseif ( 'comments' === $scope ) {
                $wpdb->update( $wpdb->comments, array( 'comment_content' => '' ), array( 'comment_ID' => absint( $id ) ) );
            }
            do_action( 'secure_shield/log', sprintf( 'Sanitized database entry %s', $identifier ), 'critical' );
        }
    }

    /**
     * Scan themes immediately after installation and quarantine malicious files.
     *
     * @param WP_Upgrader $upgrader   Upgrader instance.
     * @param array       $hook_extra Operation context.
     */
    public function scan_new_install( $upgrader, $hook_extra ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
        $type = $hook_extra['type'] ?? '';
        if ( 'theme' !== $type ) {
            return;
        }

        $themes = array();
        if ( ! empty( $hook_extra['themes'] ) ) {
            $themes = (array) $hook_extra['themes'];
        } elseif ( ! empty( $hook_extra['theme'] ) ) {
            $themes = array( $hook_extra['theme'] );
        }

        foreach ( $themes as $theme_slug ) {
            $theme_slug = sanitize_key( $theme_slug );
            $theme_root = get_theme_root( $theme_slug );
            $theme_path = wp_normalize_path( trailingslashit( $theme_root ) . $theme_slug );
            if ( empty( $theme_root ) || ! is_dir( $theme_path ) ) {
                continue;
            }

            $results = $this->scan( 'targeted', array( $theme_path ) );
            if ( ! empty( $results['critical'] ) && $this->remediator ) {
                $quarantine = $this->remediator->quarantine_items( array_keys( $results['critical'] ) );
                if ( ! empty( $quarantine ) ) {
                    $results['quarantined'] = array_merge( $results['quarantined'], $quarantine );
                }
            }

            update_option( 'secure_shield_theme_scan_' . $theme_slug, $results, false );
            $history = get_option( 'secure_shield_theme_scan_history', array() );
            $history[ $theme_slug ] = array(
                'time'        => current_time( 'timestamp' ),
                'critical'    => $results['critical'],
                'quarantined' => $results['quarantined'],
                'ai_guidance' => $results['ai_guidance'],
            );
            update_option( 'secure_shield_theme_scan_history', $history, false );

            if ( ! empty( $results['critical'] ) ) {
                $this->notify_admin(
                    $results,
                    sprintf(
                        __( 'BISON Security Suite isolated files during the %s theme install.', SECURE_SHIELD_TEXT_DOMAIN ),
                        $theme_slug
                    )
                );
            }
        }
    }

    /**
     * Notify administrators via email.
     *
     * @param array  $results        Scan results.
     * @param string $custom_message Optional message override.
     */
    protected function notify_admin( $results, $custom_message = '' ) {
        $admin_email = get_option( 'admin_email' );
        wp_mail(
            $admin_email,
            __( 'BISON Security Suite Alert: Critical Threats Detected', SECURE_SHIELD_TEXT_DOMAIN ),
            sprintf(
                "%s\n\n%s",
                $custom_message ? wp_strip_all_tags( $custom_message ) : __( 'BISON Security Suite detected critical issues during the latest scan.', SECURE_SHIELD_TEXT_DOMAIN ),
                print_r( $results['critical'], true )
            )
        );
    }
}
