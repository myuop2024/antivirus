<?php
/**
 * Schedules routine scans and maintenance tasks.
 *
 * @package Secure_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Secure_Shield_Scheduler {

    /**
     * Scanner instance.
     *
     * @var Secure_Shield_Scanner
     */
    protected $scanner;

    /**
     * Permissions checker.
     *
     * @var Secure_Shield_Permissions
     */
    protected $permissions;

    /**
     * Firewall instance.
     *
     * @var Secure_Shield_Firewall
     */
    protected $firewall;

    /**
     * Logger instance.
     *
     * @var Secure_Shield_Logger
     */
    protected $logger;

    /**
     * Constructor.
     *
     * @param Secure_Shield_Scanner     $scanner Scanner instance.
     * @param Secure_Shield_Permissions $permissions Permissions.
     * @param Secure_Shield_Firewall    $firewall Firewall.
     * @param Secure_Shield_Logger      $logger Logger.
     */
    public function __construct( Secure_Shield_Scanner $scanner, Secure_Shield_Permissions $permissions, Secure_Shield_Firewall $firewall, Secure_Shield_Logger $logger ) {
        $this->scanner     = $scanner;
        $this->permissions = $permissions;
        $this->firewall    = $firewall;
        $this->logger      = $logger;
    }

    /**
     * Register cron schedules and actions.
     */
    public function register() {
        add_filter( 'cron_schedules', array( $this, 'register_custom_schedules' ) );
        add_action( 'secure_shield_daily_scan', array( $this, 'execute_daily_scan' ) );
        add_action( 'secure_shield_hourly_maintenance', array( $this, 'execute_hourly_tasks' ) );

        if ( ! wp_next_scheduled( 'secure_shield_daily_scan' ) ) {
            wp_schedule_event( time(), 'secure_shield_6h', 'secure_shield_daily_scan' );
        }

        if ( ! wp_next_scheduled( 'secure_shield_hourly_maintenance' ) ) {
            wp_schedule_event( time(), 'hourly', 'secure_shield_hourly_maintenance' );
        }
    }

    /**
     * Define custom cron schedules.
     *
     * @param array $schedules Existing schedules.
     *
     * @return array
     */
    public function register_custom_schedules( $schedules ) {
        $schedules['secure_shield_6h'] = array(
            'interval' => 6 * HOUR_IN_SECONDS,
            'display'  => __( 'Every 6 Hours (BISON Security Suite)', SECURE_SHIELD_TEXT_DOMAIN ),
        );
        $schedules['secure_shield_5m'] = array(
            'interval' => 5 * MINUTE_IN_SECONDS,
            'display'  => __( 'Every 5 Minutes (BISON Security Suite)', SECURE_SHIELD_TEXT_DOMAIN ),
        );
        return $schedules;
    }

    /**
     * Execute daily scan routine.
     */
    public function execute_daily_scan() {
        do_action( 'secure_shield_run_scan', 'deep', array() );
        do_action( 'secure_shield/log', __( 'Scheduled deep scan executed.', SECURE_SHIELD_TEXT_DOMAIN ) );
    }

    /**
     * Execute hourly tasks.
     */
    public function execute_hourly_tasks() {
        $issues = $this->permissions->check_permissions();
        if ( ! empty( $issues ) ) {
            update_option( 'secure_shield_permission_issues', $issues, false );
        }

        $blocklist = $this->firewall->get_blocklist();
        if ( is_array( $blocklist ) ) {
            foreach ( $blocklist as $ip => $details ) {
                if ( time() - $details['time'] > DAY_IN_SECONDS ) {
                    unset( $blocklist[ $ip ] );
                }
            }
            set_site_transient( 'secure_shield_blocklist', $blocklist, DAY_IN_SECONDS * 7 );
        }

        do_action( 'secure_shield/log', __( 'Hourly maintenance completed.', SECURE_SHIELD_TEXT_DOMAIN ), 'info' );
    }
}
