<?php
/**
 * DeepSeek V3.1 AI-Powered Malware Analysis
 *
 * @package Secure_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Secure_Shield_AI_Analyzer {

	/**
	 * API endpoint URL (OpenRouter).
	 */
	const API_URL = 'https://openrouter.ai/api/v1/chat/completions';

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
	 * @param Secure_Shield_Logger   $logger   Logger instance.
	 * @param Secure_Shield_Settings $settings Settings handler.
	 */
	public function __construct( Secure_Shield_Logger $logger, Secure_Shield_Settings $settings ) {
		$this->logger   = $logger;
		$this->settings = $settings;
	}

	/**
	 * Register hooks.
	 */
	public function register() {
		// AJAX endpoint for testing API connection
		add_action( 'wp_ajax_secure_shield_test_ai', array( $this, 'ajax_test_connection' ) );
	}

	/**
	 * Check if AI analysis is enabled and configured.
	 *
	 * @return bool
	 */
	public function is_enabled() {
		return $this->settings->is_ai_enabled() && ! empty( $this->settings->get_deepseek_api_key() );
	}

	/**
	 * Analyze suspicious code for threats.
	 *
	 * @param string $code      The code to analyze.
	 * @param string $file_path File path for context.
	 * @param array  $detections Existing signature-based detections.
	 *
	 * @return array|false Analysis results or false on failure.
	 */
	public function analyze_threat( $code, $file_path, $detections = array() ) {
		if ( ! $this->is_enabled() ) {
			return false;
		}

		$api_key = $this->settings->get_deepseek_api_key();
		if ( empty( $api_key ) ) {
			return false;
		}

		// Build context from existing detections
		$detection_context = '';
		if ( ! empty( $detections ) ) {
			$detection_context = "\n\nSignature-based detections found:\n";
			foreach ( $detections as $detection ) {
				$detection_context .= "- {$detection['description']} (Severity: {$detection['severity']})\n";
			}
		}

		$prompt = "Analyze this PHP code from '{$file_path}' for security threats.{$detection_context}\n\n```php\n" . substr( $code, 0, 8000 ) . "\n```\n\n"
				. "Provide:\n"
				. "1. Threat Assessment: Is this malicious, suspicious, or safe?\n"
				. "2. Confidence Level: Percentage (0-100%)\n"
				. "3. Threat Type: (e.g., web shell, backdoor, malware, ransomware, legitimate code)\n"
				. "4. Risk Level: critical, high, medium, low, or none\n"
				. "5. Recommended Action: quarantine, repair, whitelist, or monitor\n"
				. "6. Brief Explanation: Why you determined this assessment\n\n"
				. "Format your response as JSON.";

		$response = $this->call_api( $prompt, true, 0.1 );

		if ( is_wp_error( $response ) ) {
			do_action( 'secure_shield/log', sprintf( 'AI analysis failed: %s', $response->get_error_message() ), 'warning' );
			return false;
		}

		return $this->parse_analysis_response( $response );
	}

	/**
	 * Generate a repair for infected code.
	 *
	 * @param string $infected_code  The infected code.
	 * @param string $threat_type    Type of threat detected.
	 * @param string $file_path      File path for context.
	 *
	 * @return string|false Repaired code or false on failure.
	 */
	public function generate_repair( $infected_code, $threat_type, $file_path ) {
		if ( ! $this->is_enabled() ) {
			return false;
		}

		$prompt = "This PHP code from '{$file_path}' contains '{$threat_type}'. Generate a safe, repaired version that removes the malicious code while preserving legitimate functionality.\n\n"
				. "```php\n" . substr( $infected_code, 0, 8000 ) . "\n```\n\n"
				. "Return ONLY the repaired PHP code, no explanations.";

		$response = $this->call_api( $prompt, false, 0.1 );

		if ( is_wp_error( $response ) ) {
			do_action( 'secure_shield/log', sprintf( 'AI repair failed: %s', $response->get_error_message() ), 'warning' );
			return false;
		}

		// Extract PHP code from response
		if ( preg_match( '/```php\s*(.*?)\s*```/s', $response, $matches ) ) {
			return trim( $matches[1] );
		}

		return trim( $response );
	}

	/**
	 * Learn patterns from malware samples.
	 *
	 * @param array $samples Array of malware code samples.
	 *
	 * @return array|false Extracted patterns or false on failure.
	 */
	public function extract_patterns( $samples ) {
		if ( ! $this->is_enabled() || empty( $samples ) ) {
			return false;
		}

		$samples_text = '';
		$count = 0;
		foreach ( $samples as $sample ) {
			if ( $count++ >= 5 ) {
				break; // Limit to 5 samples to avoid token limits
			}
			$samples_text .= "Sample " . $count . ":\n```\n" . substr( $sample, 0, 2000 ) . "\n```\n\n";
		}

		$prompt = "Analyze these malware samples and extract common detection patterns:\n\n{$samples_text}\n\n"
				. "Provide:\n"
				. "1. Common patterns (regex or string signatures)\n"
				. "2. Obfuscation techniques used\n"
				. "3. Suggested detection rules\n\n"
				. "Format as JSON with 'patterns' array.";

		$response = $this->call_api( $prompt, true, 0.2 );

		if ( is_wp_error( $response ) ) {
			do_action( 'secure_shield/log', sprintf( 'AI pattern extraction failed: %s', $response->get_error_message() ), 'warning' );
			return false;
		}

		return $this->parse_pattern_response( $response );
	}

	/**
	 * Verify if flagged code is a false positive.
	 *
	 * @param string $code     Flagged code.
	 * @param string $context  Context (e.g., plugin name).
	 * @param array  $detections Signature detections.
	 *
	 * @return array|false Verification results or false on failure.
	 */
	public function verify_false_positive( $code, $context, $detections ) {
		if ( ! $this->is_enabled() ) {
			return false;
		}

		$detection_info = '';
		foreach ( $detections as $detection ) {
			$detection_info .= "- {$detection['signature']}: {$detection['description']}\n";
		}

		$prompt = "This code from '{$context}' was flagged by signature-based detection:\n\n"
				. "{$detection_info}\n\n"
				. "```php\n" . substr( $code, 0, 8000 ) . "\n```\n\n"
				. "Determine if this is:\n"
				. "1. Legitimate code (false positive)\n"
				. "2. Malicious code (true positive)\n"
				. "3. Suspicious but unclear\n\n"
				. "Provide confidence level and reasoning. Format as JSON.";

		$response = $this->call_api( $prompt, true, 0.1 );

		if ( is_wp_error( $response ) ) {
			return false;
		}

		return $this->parse_verification_response( $response );
	}

	/**
	 * Test API connection.
	 *
	 * @return array Test results.
	 */
	public function test_connection() {
		$api_key = $this->settings->get_deepseek_api_key();

		if ( empty( $api_key ) ) {
			return array(
				'success' => false,
				'message' => __( 'API key is not configured.', 'secure-shield' ),
			);
		}

		$test_prompt = 'Respond with "OK" if you can read this message.';
		$response = $this->call_api( $test_prompt, false, 0.1 );

		if ( is_wp_error( $response ) ) {
			return array(
				'success' => false,
				'message' => sprintf( __( 'Connection failed: %s', 'secure-shield' ), $response->get_error_message() ),
			);
		}

		return array(
			'success' => true,
			'message' => __( 'DeepSeek AI connected successfully!', 'secure-shield' ),
			'model'   => 'deepseek-chat (V3.1)',
		);
	}

	/**
	 * AJAX handler for testing connection.
	 */
	public function ajax_test_connection() {
		check_ajax_referer( 'secure_shield_test_ai', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'secure-shield' ) ) );
		}

		$result = $this->test_connection();

		if ( $result['success'] ) {
			wp_send_json_success( $result );
		} else {
			wp_send_json_error( $result );
		}
	}

	/**
	 * Call DeepSeek API.
	 *
	 * @param string $prompt          The prompt to send.
	 * @param bool   $reasoning       Enable reasoning mode.
	 * @param float  $temperature     Temperature setting.
	 *
	 * @return string|WP_Error Response content or error.
	 */
	protected function call_api( $prompt, $reasoning = false, $temperature = 0.1 ) {
		$api_key = $this->settings->get_deepseek_api_key();

		$body = array(
			'model'       => 'deepseek/deepseek-chat-v3.1:free', // OpenRouter model name
			'messages'    => array(
				array(
					'role'    => 'system',
					'content' => 'You are a cybersecurity expert specializing in malware analysis, threat detection, and code security. Provide accurate, actionable analysis.',
				),
				array(
					'role'    => 'user',
					'content' => $prompt,
				),
			),
			'temperature' => $temperature,
		);

		// Enable reasoning for complex analysis
		if ( $reasoning ) {
			$body['reasoning_enabled'] = true;
		}

		$response = wp_remote_post(
			self::API_URL,
			array(
				'headers' => array(
					'Authorization' => 'Bearer ' . $api_key,
					'Content-Type'  => 'application/json',
					'HTTP-Referer'  => home_url(),
					'X-Title'       => get_bloginfo( 'name' ) . ' - Secure Shield',
				),
				'body'    => wp_json_encode( $body ),
				'timeout' => 45,
			)
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			$body = wp_remote_retrieve_body( $response );
			$error = json_decode( $body, true );
			return new WP_Error(
				'api_error',
				isset( $error['error']['message'] ) ? $error['error']['message'] : sprintf( 'HTTP %d', $code )
			);
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( empty( $data['choices'][0]['message']['content'] ) ) {
			return new WP_Error( 'empty_response', 'No content in API response' );
		}

		return $data['choices'][0]['message']['content'];
	}

	/**
	 * Parse analysis response.
	 *
	 * @param string $response API response.
	 *
	 * @return array Parsed results.
	 */
	protected function parse_analysis_response( $response ) {
		// Try to extract JSON from response
		if ( preg_match( '/\{[^{}]*"threat_assessment"[^{}]*\}/s', $response, $matches ) ) {
			$json = json_decode( $matches[0], true );
			if ( $json ) {
				return $json;
			}
		}

		// Fallback: Parse key-value format
		$result = array(
			'threat_assessment' => 'unknown',
			'confidence'        => 0,
			'threat_type'       => 'unknown',
			'risk_level'        => 'medium',
			'recommended_action' => 'review',
			'explanation'       => $response,
		);

		if ( preg_match( '/confidence.*?(\d+)%?/i', $response, $matches ) ) {
			$result['confidence'] = intval( $matches[1] );
		}

		if ( preg_match( '/threat.*?assessment.*?:?\s*(\w+)/i', $response, $matches ) ) {
			$result['threat_assessment'] = strtolower( $matches[1] );
		}

		if ( preg_match( '/risk.*?level.*?:?\s*(\w+)/i', $response, $matches ) ) {
			$result['risk_level'] = strtolower( $matches[1] );
		}

		return $result;
	}

	/**
	 * Parse pattern extraction response.
	 *
	 * @param string $response API response.
	 *
	 * @return array Extracted patterns.
	 */
	protected function parse_pattern_response( $response ) {
		if ( preg_match( '/\{[^{}]*"patterns"[^{}]*\}/s', $response, $matches ) ) {
			$json = json_decode( $matches[0], true );
			if ( $json && isset( $json['patterns'] ) ) {
				return $json['patterns'];
			}
		}

		// Fallback: Extract patterns from text
		$patterns = array();
		if ( preg_match_all( '/regex:([^\n]+)/i', $response, $matches ) ) {
			foreach ( $matches[1] as $pattern ) {
				$patterns[] = 'regex:' . trim( $pattern );
			}
		}

		return $patterns;
	}

	/**
	 * Parse verification response.
	 *
	 * @param string $response API response.
	 *
	 * @return array Verification results.
	 */
	protected function parse_verification_response( $response ) {
		$result = array(
			'is_false_positive' => false,
			'confidence'        => 0,
			'reasoning'         => $response,
		);

		if ( preg_match( '/legitimate|false.*?positive/i', $response ) ) {
			$result['is_false_positive'] = true;
		}

		if ( preg_match( '/confidence.*?(\d+)%?/i', $response, $matches ) ) {
			$result['confidence'] = intval( $matches[1] );
		}

		return $result;
	}
}
