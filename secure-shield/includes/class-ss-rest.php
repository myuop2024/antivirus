<?php
/**
 * REST API endpoints for BISON Security Suite.
 *
 * @package Secure_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Secure_Shield_REST {

    /**
     * Scanner instance.
     *
     * @var Secure_Shield_Scanner
     */
    protected $scanner;

    /**
     * Logger instance.
     *
     * @var Secure_Shield_Logger
     */
    protected $logger;

    /**
     * Firewall instance.
     *
     * @var Secure_Shield_Firewall
     */
    protected $firewall;

    /**
     * Constructor.
     *
     * @param Secure_Shield_Scanner  $scanner  Scanner instance.
     * @param Secure_Shield_Logger   $logger   Logger instance.
     * @param Secure_Shield_Firewall $firewall Firewall instance.
     */
    public function __construct( Secure_Shield_Scanner $scanner, Secure_Shield_Logger $logger, Secure_Shield_Firewall $firewall ) {
        $this->scanner  = $scanner;
        $this->logger   = $logger;
        $this->firewall = $firewall;
    }

    /**
     * Register REST routes.
     */
    public function register() {
        add_action( 'rest_api_init', array( $this, 'register_routes' ) );
    }

    /**
     * Register plugin routes.
     */
    public function register_routes() {
        register_rest_route(
            'secure-shield/v1',
            '/scan',
            array(
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => array( $this, 'handle_scan' ),
                'permission_callback' => array( $this, 'permissions_check' ),
                'args'                => array(
                    'type' => array(
                        'type'    => 'string',
                        'default' => 'quick',
                    ),
                ),
            )
        );

        register_rest_route(
            'secure-shield/v1',
            '/results',
            array(
                'methods'             => WP_REST_Server::READABLE,
                'callback'            => array( $this, 'get_results' ),
                'permission_callback' => array( $this, 'permissions_check' ),
            )
        );
    }

    /**
     * Handle scan request.
     *
     * @param WP_REST_Request $request Request.
     *
     * @return WP_REST_Response
     */
    public function handle_scan( WP_REST_Request $request ) {
        $scan_type = $request->get_param( 'type' );
        $results   = $this->scanner->scan( $scan_type );

        return new WP_REST_Response( $results, 200 );
    }

    /**
     * Retrieve latest results.
     *
     * @return WP_REST_Response
     */
    public function get_results() {
        $results = get_option( Secure_Shield_Scanner::OPTION_SCAN_RESULTS, array() );
        return new WP_REST_Response( $results, 200 );
    }

    /**
     * Check permissions for REST actions.
     *
     * @return bool
     */
    public function permissions_check() {
        if ( $this->firewall->current_ip_is_blocked() ) {
            return new WP_Error( 'secure_shield_blocked', __( 'Your IP has been blocked by the security firewall.', SECURE_SHIELD_TEXT_DOMAIN ), array( 'status' => 403 ) );
        }

        if ( ! current_user_can( 'manage_options' ) ) {
            return new WP_Error( 'secure_shield_forbidden', __( 'You do not have permission to access BISON Security Suite endpoints.', SECURE_SHIELD_TEXT_DOMAIN ), array( 'status' => rest_authorization_required_code() ) );
        }

        return true;
    }
}
