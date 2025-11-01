<?php
/**
 * REST API endpoints for Secure Shield.
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
     * Constructor.
     *
     * @param Secure_Shield_Scanner $scanner Scanner instance.
     * @param Secure_Shield_Logger  $logger Logger instance.
     */
    public function __construct( Secure_Shield_Scanner $scanner, Secure_Shield_Logger $logger ) {
        $this->scanner = $scanner;
        $this->logger  = $logger;
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
        return current_user_can( 'manage_options' );
    }
}
