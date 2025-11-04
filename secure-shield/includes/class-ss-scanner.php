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
        $basename = basename( $file_path );
        $relevant_extensions = array( 'php', 'js', 'html', 'htm', 'phtml', 'php3', 'php4', 'php5', 'pht', 'phps' );

        // Check for suspicious filenames
        $suspicious_names = array(
            'regex:/\.(php|phtml)\.(jpg|png|gif|txt|log)$/i' => __( 'Double extension detected (possible obfuscation)', 'secure-shield' ),
            'regex:/^(shell|backdoor|cmd|c99|r57|wso|b374k)/i' => __( 'Suspicious filename pattern', 'secure-shield' ),
            'regex:/^\./i' => __( 'Hidden file detected', 'secure-shield' ),
        );

        $file_relative = str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $file_path ) );

        foreach ( $suspicious_names as $pattern => $description ) {
            if ( 0 === strpos( $pattern, 'regex:' ) ) {
                $regex_pattern = substr( $pattern, 6 );
                if ( @preg_match( $regex_pattern, $basename ) ) {
                    $results['warnings'][ $file_relative ] = $description;
                }
            }
        }

        if ( ! in_array( $ext, $relevant_extensions, true ) ) {
            return;
        }

        // Cloud-optimized: Increased limit to 100MB for Google Cloud infrastructure
        // Can be configured via filter: apply_filters('secure_shield_max_file_size', 104857600)
        $max_filesize = apply_filters( 'secure_shield_max_file_size', 104857600 ); // 100MB default
        $filesize = @filesize( $file_path );

        if ( false === $filesize ) {
            return;
        }

        if ( $filesize > $max_filesize ) {
            $results['info'][ $file_relative ] = sprintf(
                __( 'File exceeds maximum scan size (%s), skipped. Use secure_shield_max_file_size filter to adjust.', 'secure-shield' ),
                size_format( $max_filesize )
            );
            return;
        }

        // For very large files, use chunked reading to be memory-efficient
        if ( $filesize > 10485760 ) { // 10MB
            $contents = $this->read_file_chunked( $file_path, $filesize );
        } else {
            $contents = @file_get_contents( $file_path );
        }

        if ( false === $contents ) {
            return;
        }

        foreach ( $signatures as $signature => $description ) {
            $is_regex = 0 === strpos( $signature, 'regex:' );

            if ( $is_regex ) {
                $pattern = substr( $signature, 6 );
                $match   = @preg_match( $pattern, $contents );

                if ( false === $match || 1 !== $match ) {
                    continue;
                }
            } elseif ( stripos( $contents, $signature ) === false ) {
                continue;
            }

            $severity = $this->determine_severity( $signature );

            $results['files'][ $file_relative ][] = array(
                'signature'   => $is_regex ? 'regex: ' . $pattern : $signature,
                'description' => $description,
                'severity'    => $severity,
            );

            if ( 'critical' === $severity ) {
                $results['critical'][ $file_relative ] = $description;
            }
        }

        $checksum = md5( $contents );
        $stored   = get_site_option( 'secure_shield_checksums', array() );
        if ( isset( $stored[ $file_relative ] ) && $stored[ $file_relative ] !== $checksum ) {
            $results['warnings'][ $file_relative ] = __( 'File integrity mismatch detected.', 'secure-shield' );
        }
        $stored[ $file_relative ] = $checksum;
        update_site_option( 'secure_shield_checksums', $stored );
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
                $results['integrity']['core'][ $file ] = __( 'Core file missing from installation.', 'secure-shield' );
                $results['critical'][ 'core:' . $file ] = __( 'Core file missing from installation.', 'secure-shield' );
                continue;
            }

            $contents = @file_get_contents( $full_path );
            if ( false === $contents ) {
                continue;
            }

            $hash = md5( $contents );
            if ( strtolower( $hash ) !== strtolower( $checksum ) ) {
                $results['integrity']['core'][ $file ] = __( 'Core file integrity mismatch detected.', 'secure-shield' );
                $results['critical'][ 'core:' . $file ] = __( 'Core file integrity mismatch detected.', 'secure-shield' );

                if ( $this->settings && $this->settings->is_auto_repair_enabled() && $this->remediator ) {
                    $repair = $this->remediator->maybe_repair_core_file( $file );
                    if ( is_wp_error( $repair ) ) {
                        $results['warnings'][ 'core:' . $file ] = $repair->get_error_message();
                    } else {
                        $results['info'][ 'core:' . $file ] = __( 'Core file automatically repaired using trusted source.', 'secure-shield' );
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
            'postmeta' => array(
                'table' => $wpdb->postmeta,
                'id'    => 'meta_id',
                'field' => 'meta_value',
            ),
            'options'  => array(
                'table' => $wpdb->options,
                'id'    => 'option_id',
                'field' => 'option_value',
            ),
        );

        foreach ( $targets as $type => $meta ) {
            $id_field    = $meta['id'];
            $content_key = $meta['field'];
            $table       = $meta['table'];

            // Cloud-optimized: Scan all rows by default, configurable via filter
            // apply_filters('secure_shield_db_scan_limit', 0) where 0 = unlimited
            $scan_limit = apply_filters( 'secure_shield_db_scan_limit', 0 ); // 0 = scan all

            if ( $scan_limit > 0 ) {
                $rows = $wpdb->get_results( $wpdb->prepare( "SELECT {$id_field} as id, {$content_key} as content FROM {$table} ORDER BY {$id_field} DESC LIMIT %d", $scan_limit ), ARRAY_A );
            } else {
                // Scan all rows for comprehensive protection
                $rows = $wpdb->get_results( "SELECT {$id_field} as id, {$content_key} as content FROM {$table} ORDER BY {$id_field} DESC", ARRAY_A );
            }

            foreach ( (array) $rows as $row ) {
                $content = $row['content'] ?? '';

                // Skip empty or very short content
                if ( empty( $content ) || strlen( $content ) < 10 ) {
                    continue;
                }

                foreach ( $signatures as $signature => $description ) {
                    $is_regex = 0 === strpos( $signature, 'regex:' );
                    $matched = false;

                    if ( $is_regex ) {
                        $pattern = substr( $signature, 6 );
                        $matched = @preg_match( $pattern, $content );
                    } elseif ( stripos( $content, $signature ) !== false ) {
                        $matched = true;
                    }

                    if ( $matched ) {
                        $key = $type . ':' . $row['id'];
                        $severity = $this->determine_severity( $signature );

                        $results['database'][ $key ][] = array(
                            'signature'   => $signature,
                            'description' => $description,
                            'severity'    => $severity,
                        );

                        if ( 'critical' === $severity ) {
                            $results['critical'][ $key ] = $description;
                        }
                    }
                }
            }
        }
    }

    /**
     * Read large files in chunks for memory efficiency.
     *
     * @param string $file_path File path.
     * @param int    $filesize  File size in bytes.
     *
     * @return string|false
     */
    protected function read_file_chunked( $file_path, $filesize ) {
        $chunk_size = 8192; // 8KB chunks
        $handle = @fopen( $file_path, 'rb' );

        if ( false === $handle ) {
            return false;
        }

        $content = '';
        while ( ! feof( $handle ) ) {
            $chunk = fread( $handle, $chunk_size );
            if ( false === $chunk ) {
                fclose( $handle );
                return false;
            }
            $content .= $chunk;
        }

        fclose( $handle );
        return $content;
    }

    /**
     * Determine severity for a given signature.
     *
     * @param string $signature Signature string.
     *
     * @return string
     */
    protected function determine_severity( $signature ) {
        if ( 0 === strpos( $signature, 'regex:' ) ) {
            $signature = substr( $signature, 6 );
        }

        // Critical threats - immediate action required
        $critical_patterns = array(
            'eval(',
            'shell_exec(',
            'exec(',
            'passthru(',
            'system(',
            'proc_open(',
            'popen(',
            'pcntl_exec(',
            'assert(',
            'create_function(',
            'preg_replace.*\/e',
            'c99shell',
            'r57shell',
            'wso shell',
            'b374k',
            'unserialize.*\$_(GET|POST|REQUEST|COOKIE)',
            '\$_(GET|POST|REQUEST)\[.*\]\s*\(',
            'socket_create.*socket_connect',
            'proc_open.*descriptorspec',
            'fsockopen.*\/bin\/(bash|sh)',
            'FilesMan',
            'Remoteshell',
            'base64_decode(',
            'gzinflate(',
            'gzuncompress(',
            'str_rot13(',
            'encrypted|locked|crypto',
            'pay.*bitcoin',
        );

        foreach ( $critical_patterns as $pattern ) {
            if ( false !== stripos( $signature, $pattern ) ) {
                return 'critical';
            }
        }

        // Everything else is a warning
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
            $full_path = wp_normalize_path( ABSPATH . ltrim( $identifier, '/' ) );
            if ( file_exists( $full_path ) ) {
                $backup_dir = WP_CONTENT_DIR . '/secure-shield-quarantine';
                wp_mkdir_p( $backup_dir );
                $destination = wp_normalize_path( $backup_dir . '/' . basename( $full_path ) . '-' . time() );
                if ( @copy( $full_path, $destination ) ) {
                    unlink( $full_path );
                    do_action( 'secure_shield/log', sprintf( 'Quarantined and removed file %s', $identifier ), 'critical' );
                }
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
     * Notify administrators via email.
     *
     * @param array $results Scan results.
     */
    protected function notify_admin( $results ) {
        $admin_email = get_option( 'admin_email' );
        wp_mail(
            $admin_email,
            __( 'Secure Shield Critical Issues Detected', 'secure-shield' ),
            sprintf(
                "%s\n\n%s",
                __( 'Secure Shield detected critical issues during the latest scan.', 'secure-shield' ),
                print_r( $results['critical'], true )
            )
        );
    }
}
