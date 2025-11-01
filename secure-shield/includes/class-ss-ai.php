<?php
/**
 * AI assisted remediation guidance.
 *
 * @package Secure_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Secure_Shield_AI_Assistant {

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
     * Provide AI generated guidance for a suspicious artifact.
     *
     * @param string $file_path Absolute file path.
     * @param array  $context   Context array containing signature, description, and snippet.
     *
     * @return array
     */
    public function generate_guidance( $file_path, array $context = array() ) {
        $suggestions = array();
        $prompt      = $this->build_prompt( $file_path, $context );

        if ( empty( $prompt ) ) {
            return $suggestions;
        }

        $gemini_key = $this->settings->get_gemini_api_key();
        if ( ! empty( $gemini_key ) ) {
            $gemini_response = $this->query_gemini( $prompt, $gemini_key, $this->settings->get_gemini_model() );
            if ( ! empty( $gemini_response ) ) {
                $suggestions['gemini'] = $gemini_response;
            }
        }

        $hf_key = $this->settings->get_hf_api_key();
        if ( ! empty( $hf_key ) ) {
            $hf_response = $this->query_huggingface( $prompt, $hf_key, $this->settings->get_hf_model() );
            if ( ! empty( $hf_response ) ) {
                $suggestions['huggingface'] = $hf_response;
            }
        }

        return $suggestions;
    }

    /**
     * Construct a concise prompt for LLM requests.
     *
     * @param string $file_path Absolute file path.
     * @param array  $context   Context information.
     *
     * @return string
     */
    protected function build_prompt( $file_path, array $context ) {
        $summary = array();
        $summary[] = 'Provide step-by-step remediation advice for the suspicious code below.';
        $summary[] = 'Do not include destructive commands and assume the responder has WordPress expertise.';

        if ( ! empty( $context['description'] ) ) {
            $summary[] = 'Indicator: ' . sanitize_text_field( $context['description'] );
        }

        if ( ! empty( $context['signature'] ) ) {
            $summary[] = 'Signature: ' . sanitize_text_field( $context['signature'] );
        }

        $summary[] = 'File: ' . wp_normalize_path( $file_path );

        $snippet = $context['snippet'] ?? '';
        if ( ! empty( $snippet ) ) {
            $snippet = wp_strip_all_tags( $snippet );
            $snippet = substr( $snippet, 0, 2000 );
            $summary[] = 'Snippet:';
            $summary[] = $snippet;
        }

        return implode( "\n", $summary );
    }

    /**
     * Query Gemini API for remediation guidance.
     *
     * @param string $prompt Prompt text.
     * @param string $api_key API key.
     * @param string $model Model identifier.
     *
     * @return string
     */
    protected function query_gemini( $prompt, $api_key, $model ) {
        $url  = sprintf( 'https://generativelanguage.googleapis.com/v1beta/%1$s:generateContent?key=%2$s', rawurlencode( $model ), rawurlencode( $api_key ) );
        $body = wp_json_encode(
            array(
                'contents' => array(
                    array(
                        'parts' => array(
                            array(
                                'text' => $prompt,
                            ),
                        ),
                    ),
                ),
            )
        );

        $response = wp_remote_post(
            $url,
            array(
                'timeout' => 30,
                'headers' => array(
                    'Content-Type' => 'application/json',
                ),
                'body'    => $body,
            )
        );

        if ( is_wp_error( $response ) ) {
            do_action( 'secure_shield/log', sprintf( 'Gemini request failed: %s', $response->get_error_message() ), 'warning' );
            return '';
        }

        $data = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( empty( $data['candidates'][0]['content']['parts'][0]['text'] ) ) {
            return '';
        }

        return wp_strip_all_tags( $data['candidates'][0]['content']['parts'][0]['text'] );
    }

    /**
     * Query Hugging Face for remediation guidance.
     *
     * @param string $prompt Prompt text.
     * @param string $api_key API key.
     * @param string $model Model identifier.
     *
     * @return string
     */
    protected function query_huggingface( $prompt, $api_key, $model ) {
        $url      = sprintf( 'https://api-inference.huggingface.co/models/%s', rawurlencode( $model ) );
        $response = wp_remote_post(
            $url,
            array(
                'timeout' => 45,
                'headers' => array(
                    'Authorization' => 'Bearer ' . $api_key,
                    'Content-Type'  => 'application/json',
                ),
                'body'    => wp_json_encode(
                    array(
                        'inputs' => $prompt,
                    )
                ),
            )
        );

        if ( is_wp_error( $response ) ) {
            do_action( 'secure_shield/log', sprintf( 'Hugging Face request failed: %s', $response->get_error_message() ), 'warning' );
            return '';
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( empty( $body ) ) {
            return '';
        }

        if ( isset( $body[0]['generated_text'] ) ) {
            return wp_strip_all_tags( $body[0]['generated_text'] );
        }

        if ( isset( $body['generated_text'] ) ) {
            return wp_strip_all_tags( $body['generated_text'] );
        }

        if ( isset( $body['error'] ) ) {
            do_action( 'secure_shield/log', sprintf( 'Hugging Face response error: %s', $body['error'] ), 'warning' );
        }

        return '';
    }
}
