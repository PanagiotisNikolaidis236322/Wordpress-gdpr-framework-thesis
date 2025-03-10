<?php
namespace GDPRFramework\Components;

/**
 * Network Configuration Manager
 * 
 * Provides support for load balancing, CDN, and scalability
 * as specified in Appendix A
 */
class NetworkConfiguration {
    private $settings;
    private $is_behind_load_balancer = false;
    private $is_using_cdn = false;
    private $cdn_url = '';
    private $debug = false;

    public function __construct($settings) {
        $this->settings = $settings;
        $this->debug = defined('WP_DEBUG') && WP_DEBUG;
        
        // Detect load balancer and CDN
        $this->detectEnvironment();
        
        // Register hooks
        add_action('admin_init', [$this, 'registerSettings']);
        
        // Apply CDN URL filter if enabled
        if ($this->is_using_cdn) {
            add_filter('plugins_url', [$this, 'replaceCDNUrl'], 10, 3);
            add_filter('wp_get_attachment_url', [$this, 'replaceCDNUrl'], 10, 1);
        }
        
        // Adjust for load balancer IP handling
        if ($this->is_behind_load_balancer) {
            add_filter('gdpr_real_ip', [$this, 'getRealIPBehindLoadBalancer']);
        }
    }
    
    /**
     * Register settings for network configuration
     */
    public function registerSettings() {
        register_setting('gdpr_framework_settings', 'gdpr_behind_load_balancer', [
            'type' => 'boolean',
            'default' => 0,
            'sanitize_callback' => 'absint'
        ]);
        
        register_setting('gdpr_framework_settings', 'gdpr_cdn_enabled', [
            'type' => 'boolean',
            'default' => 0,
            'sanitize_callback' => 'absint'
        ]);
        
        register_setting('gdpr_framework_settings', 'gdpr_cdn_url', [
            'type' => 'string',
            'default' => '',
            'sanitize_callback' => 'esc_url_raw'
        ]);
        
        register_setting('gdpr_framework_settings', 'gdpr_trusted_proxies', [
            'type' => 'string',
            'default' => '',
            'sanitize_callback' => [$this, 'sanitizeIPList']
        ]);
        
        // Register settings section and fields
        add_settings_section(
            'gdpr_network_section',
            __('Network Configuration', 'wp-gdpr-framework'),
            [$this, 'renderNetworkSectionDescription'],
            'gdpr_framework_settings'
        );
        
        add_settings_field(
            'gdpr_behind_load_balancer',
            __('Behind Load Balancer', 'wp-gdpr-framework'),
            [$this, 'renderLoadBalancerField'],
            'gdpr_framework_settings',
            'gdpr_network_section'
        );
        
        add_settings_field(
            'gdpr_trusted_proxies',
            __('Trusted Proxy IPs', 'wp-gdpr-framework'),
            [$this, 'renderTrustedProxiesField'],
            'gdpr_framework_settings',
            'gdpr_network_section'
        );
        
        add_settings_field(
            'gdpr_cdn_enabled',
            __('Use CDN for GDPR Assets', 'wp-gdpr-framework'),
            [$this, 'renderCDNEnabledField'],
            'gdpr_framework_settings',
            'gdpr_network_section'
        );
        
        add_settings_field(
            'gdpr_cdn_url',
            __('CDN Base URL', 'wp-gdpr-framework'),
            [$this, 'renderCDNUrlField'],
            'gdpr_framework_settings',
            'gdpr_network_section'
        );
    }
    
    /**
     * Render network section description
     */
    public function renderNetworkSectionDescription() {
        echo '<p>' . esc_html__('Configure settings for load balancing and content delivery networks (CDN).', 'wp-gdpr-framework') . '</p>';
    }
    
    /**
     * Render load balancer field
     */
    public function renderLoadBalancerField() {
        $enabled = get_option('gdpr_behind_load_balancer', 0);
        
        echo '<input type="checkbox" id="gdpr_behind_load_balancer" name="gdpr_behind_load_balancer" value="1" ' . 
             checked($enabled, 1, false) . '>';
             
        echo '<p class="description">' . 
             esc_html__('Enable if your site is behind a load balancer, reverse proxy, or CDN.', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Render trusted proxies field
     */
    public function renderTrustedProxiesField() {
        $proxies = get_option('gdpr_trusted_proxies', '');
        
        echo '<textarea id="gdpr_trusted_proxies" name="gdpr_trusted_proxies" rows="3" cols="40" class="regular-text">' . 
             esc_textarea($proxies) . '</textarea>';
             
        echo '<p class="description">' . 
             esc_html__('Enter trusted proxy IP addresses (one per line).', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Render CDN enabled field
     */
    public function renderCDNEnabledField() {
        $enabled = get_option('gdpr_cdn_enabled', 0);
        
        echo '<input type="checkbox" id="gdpr_cdn_enabled" name="gdpr_cdn_enabled" value="1" ' . 
             checked($enabled, 1, false) . '>';
             
        echo '<p class="description">' . 
             esc_html__('Enable to serve GDPR assets (JS, CSS, etc.) from a CDN.', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Render CDN URL field
     */
    public function renderCDNUrlField() {
        $url = get_option('gdpr_cdn_url', '');
        
        echo '<input type="url" id="gdpr_cdn_url" name="gdpr_cdn_url" value="' . 
             esc_attr($url) . '" class="regular-text">';
             
        echo '<p class="description">' . 
             esc_html__('The base URL of your CDN (e.g., https://cdn.example.com).', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Sanitize IP list input
     */
    public function sanitizeIPList($input) {
        $ips = explode("\n", $input);
        $valid_ips = [];
        
        foreach ($ips as $ip) {
            $ip = trim($ip);
            
            if (empty($ip)) {
                continue;
            }
            
            // Validate IPv4 or IPv6 address
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $valid_ips[] = $ip;
            }
        }
        
        return implode("\n", $valid_ips);
    }
    
    /**
     * Detect environment (load balancer, CDN)
     */
    private function detectEnvironment() {
        // Check if behind load balancer (from settings or auto-detect)
        $this->is_behind_load_balancer = get_option('gdpr_behind_load_balancer', 0) || 
                                         $this->autoDetectLoadBalancer();
        
        // Check if using CDN
        $this->is_using_cdn = get_option('gdpr_cdn_enabled', 0);
        $this->cdn_url = get_option('gdpr_cdn_url', '');
        
        if ($this->debug) {
            error_log('GDPR Framework - Network Detection: ' . 
                     'Load Balancer: ' . ($this->is_behind_load_balancer ? 'Yes' : 'No') . ', ' .
                     'CDN: ' . ($this->is_using_cdn ? 'Yes' : 'No'));
        }
    }
    
    /**
     * Auto-detect if site is behind a load balancer
     */
    private function autoDetectLoadBalancer() {
        $load_balancer_headers = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'HTTP_X_REAL_IP'
        ];
        
        foreach ($load_balancer_headers as $header) {
            if (!empty($_SERVER[$header])) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Get real IP address when behind a load balancer
     */
    public function getRealIPBehindLoadBalancer($ip) {
        $load_balancer_headers = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'HTTP_X_REAL_IP'
        ];
        
        $trusted_proxies = array_filter(array_map('trim', explode("\n", get_option('gdpr_trusted_proxies', ''))));
        
        foreach ($load_balancer_headers as $header) {
            if (!empty($_SERVER[$header])) {
                $header_value = $_SERVER[$header];
                
                // Handle comma-separated list of IPs
                if (strpos($header_value, ',') !== false) {
                    $ips = array_map('trim', explode(',', $header_value));
                    
                    // If we have trusted proxies configured
                    if (!empty($trusted_proxies)) {
                        // Get the first non-trusted IP (client IP)
                        foreach ($ips as $header_ip) {
                            if (!in_array($header_ip, $trusted_proxies, true)) {
                                $client_ip = $header_ip;
                                break;
                            }
                        }
                        
                        // If we found a non-trusted IP, use it
                        if (!empty($client_ip) && filter_var($client_ip, FILTER_VALIDATE_IP)) {
                            return $client_ip;
                        }
                    }
                    
                    // If no trusted proxies or no non-trusted IP found, use first IP
                    $first_ip = $ips[0];
                    
                    if (filter_var($first_ip, FILTER_VALIDATE_IP)) {
                        return $first_ip;
                    }
                } else {
                    // Single IP
                    if (filter_var($header_value, FILTER_VALIDATE_IP)) {
                        return $header_value;
                    }
                }
            }
        }
        
        // Fallback to original IP
        return $ip;
    }
    
    /**
     * Replace local URLs with CDN URLs
     */
    public function replaceCDNUrl($url, $path = '', $plugin = '') {
        // Make sure CDN URL is set
        if (empty($this->cdn_url)) {
            return $url;
        }
        
        // Get site URL and CDN URL without protocols
        $site_url = preg_replace('/^https?:\/\//', '', site_url());
        $cdn_url = preg_replace('/^https?:\/\//', '', rtrim($this->cdn_url, '/'));
        
        // Replace site URL with CDN URL
        return str_replace($site_url, $cdn_url, $url);
    }
    
    /**
     * Get network configuration info
     */
    public function getNetworkInfo() {
        return [
            'load_balancer' => $this->is_behind_load_balancer,
            'cdn_enabled' => $this->is_using_cdn,
            'cdn_url' => $this->cdn_url,
            'real_ip' => $this->is_behind_load_balancer ? 
                        $this->getRealIPBehindLoadBalancer($_SERVER['REMOTE_ADDR'] ?? '') : 
                        ($_SERVER['REMOTE_ADDR'] ?? '')
        ];
    }
}