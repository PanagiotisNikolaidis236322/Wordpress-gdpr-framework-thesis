<?php
namespace GDPRFramework\Core;

/**
 * GDPR Framework Integrator
 * 
 * Central integration component that coordinates all GDPR compliance mechanisms
 * and provides unified API for plugins and themes to implement GDPR compliance.
 */
class GDPRIntegrator {
    private $framework;
    private $consent;
    private $retention;
    private $encryption;
    private $portability;
    private $audit;
    
    /**
     * Constructor
     */
    public function __construct() {
        $this->framework = GDPRFramework::getInstance();
        
        // Initialize components
        $this->initializeComponents();
        
        // Register hooks
        add_action('init', [$this, 'registerShortcodes']);
        
        // Register API hooks
        add_action('rest_api_init', [$this, 'registerRESTRoutes']);
        
        // Add AJAX handlers for frontend
        add_action('wp_ajax_gdpr_check_compliance', [$this, 'handleComplianceCheck']);
        add_action('wp_ajax_nopriv_gdpr_check_compliance', [$this, 'handleComplianceCheck']);
        
        // Register plugin integrations
        $this->registerPluginIntegrations();
    }
    
    /**
     * Initialize components
     */
    private function initializeComponents() {
        $this->consent = $this->framework->getComponent('consent');
        $this->retention = $this->framework->getComponent('retention');
        $this->encryption = $this->framework->getComponent('encryption');
        $this->portability = $this->framework->getComponent('portability');
        $this->audit = $this->framework->getComponent('audit');
    }
    
    /**
     * Register shortcodes
     */
    public function registerShortcodes() {
        add_shortcode('gdpr_compliance_status', [$this, 'renderComplianceStatus']);
        add_shortcode('gdpr_rights_summary', [$this, 'renderRightsSummary']);
        add_shortcode('gdpr_all_in_one', [$this, 'renderAllInOne']);
    }
    
    /**
     * Register REST API routes
     */
    public function registerRESTRoutes() {
        register_rest_route('gdpr/v1', '/compliance', [
            'methods' => 'GET',
            'callback' => [$this, 'restGetComplianceStatus'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            }
        ]);
        
        register_rest_route('gdpr/v1', '/statistics', [
            'methods' => 'GET',
            'callback' => [$this, 'restGetStatistics'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            }
        ]);
        
        register_rest_route('gdpr/v1', '/health', [
            'methods' => 'GET',
            'callback' => [$this, 'restGetSystemHealth'],
            'permission_callback' => function () {
                return current_user_can('manage_options');
            }
        ]);
    }
    
    /**
     * Register plugin integrations
     */
    private function registerPluginIntegrations() {
        // WooCommerce integration
        if (class_exists('WooCommerce')) {
            require_once GDPR_FRAMEWORK_PATH . 'integrations/woocommerce.php';
            new \GDPRFramework\Integrations\WooCommerce($this);
        }
        
        // Contact Form 7 integration
        if (defined('WPCF7_VERSION')) {
            require_once GDPR_FRAMEWORK_PATH . 'integrations/contact-form-7.php';
            new \GDPRFramework\Integrations\ContactForm7($this);
        }
        
        // Gravity Forms integration
        if (class_exists('GFForms')) {
            require_once GDPR_FRAMEWORK_PATH . 'integrations/gravity-forms.php';
            new \GDPRFramework\Integrations\GravityForms($this);
        }
        
        // Allow other plugins to register integrations
        do_action('gdpr_register_integrations', $this);
    }
    
    /**
     * Handle AJAX compliance check
     */
    public function handleComplianceCheck() {
        check_ajax_referer('gdpr_nonce', 'nonce');
        
        $response = [
            'consent' => $this->checkConsentCompliance(),
            'retention' => $this->checkRetentionCompliance(),
            'security' => $this->checkSecurityCompliance(),
            'rights' => $this->checkRightsCompliance(),
            'overall' => true
        ];
        
        // Check overall compliance
        foreach ($response as $key => $value) {
            if ($key !== 'overall' && !$value['compliant']) {
                $response['overall'] = false;
                break;
            }
        }
        
        wp_send_json_success($response);
    }
    
    /**
     * Check consent compliance
     * 
     * @return array Compliance status
     */
    public function checkConsentCompliance() {
        $issues = [];
        
        // Check if consent is enabled
        if (!isset($this->consent) || !method_exists($this->consent, 'getCurrentConsentVersion')) {
            $issues[] = __('Consent management is not properly initialized', 'wp-gdpr-framework');
        }
        
        // Check if required consent types are defined
        $consent_types = get_option('gdpr_consent_types', []);
        if (empty($consent_types)) {
            $issues[] = __('No consent types defined', 'wp-gdpr-framework');
        }
        
        // Check if cookie banner is enabled
        if (!get_option('gdpr_enable_cookie_banner', 1)) {
            $issues[] = __('Cookie consent banner is disabled', 'wp-gdpr-framework');
        }
        
        // Check if necessary cookies consent is defined
        $has_necessary = false;
        foreach ($consent_types as $type) {
            if (!empty($type['required'])) {
                $has_necessary = true;
                break;
            }
        }
        
        if (!$has_necessary) {
            $issues[] = __('No required consent type defined for necessary cookies', 'wp-gdpr-framework');
        }
        
        return [
            'compliant' => empty($issues),
            'issues' => $issues
        ];
    }
    
    /**
     * Check retention compliance
     * 
     * @return array Compliance status
     */
    public function checkRetentionCompliance() {
        $issues = [];
        
        // Check if retention policies are defined
        $retention_periods = get_option('gdpr_retention_periods', []);
        if (empty($retention_periods)) {
            $issues[] = __('No data retention policies defined', 'wp-gdpr-framework');
        }
        
        // Check if at least one retention policy is enabled
        $has_enabled = false;
        foreach ($retention_periods as $period) {
            if (!empty($period['enabled'])) {
                $has_enabled = true;
                break;
            }
        }
        
        if (!$has_enabled) {
            $issues[] = __('No data retention policies are enabled', 'wp-gdpr-framework');
        }
        
        // Check if cleanup is scheduled
        if (!wp_next_scheduled('gdpr_daily_cleanup')) {
            $issues[] = __('Automated data cleanup is not scheduled', 'wp-gdpr-framework');
        }
        
        return [
            'compliant' => empty($issues),
            'issues' => $issues
        ];
    }
    
    /**
     * Check security compliance
     * 
     * @return array Compliance status
     */
    public function checkSecurityCompliance() {
        $issues = [];
        
        // Check if encryption is enabled
        if (!get_option('gdpr_enable_encryption', 1)) {
            $issues[] = __('Data encryption is disabled', 'wp-gdpr-framework');
        }
        
        // Check if encryption key exists
        if (!isset($this->encryption) || !method_exists($this->encryption, 'hasActiveKey') || !$this->encryption->hasActiveKey()) {
            $issues[] = __('No active encryption key found', 'wp-gdpr-framework');
        }
        
        // Check if OpenSSL is available
        if (!extension_loaded('openssl')) {
            $issues[] = __('OpenSSL extension is not available', 'wp-gdpr-framework');
        }
        
        // Check if IP anonymization is enabled
        if (!get_option('gdpr_anonymize_ip_addresses', 1)) {
            $issues[] = __('IP address anonymization is disabled', 'wp-gdpr-framework');
        }
        
        // Check if audit logging is enabled
        if (!isset($this->audit) || !get_option('gdpr_enable_tamper_protection', 1)) {
            $issues[] = __('Tamper-proof audit logging is disabled', 'wp-gdpr-framework');
        }
        
        return [
            'compliant' => empty($issues),
            'issues' => $issues
        ];
    }
    
    /**
     * Check user rights compliance
     * 
     * @return array Compliance status
     */
    public function checkRightsCompliance() {
        $issues = [];
        
        // Check if data portability is initialized
        if (!isset($this->portability)) {
            $issues[] = __('Data portability component is not initialized', 'wp-gdpr-framework');
        }
        
        // Check if export formats are defined
        $export_formats = get_option('gdpr_export_formats', []);
        if (empty($export_formats)) {
            $issues[] = __('No data export formats defined', 'wp-gdpr-framework');
        }
        
        // Check if privacy policy page is set
        if (!get_option('gdpr_privacy_policy_page', 0)) {
            $issues[] = __('Privacy policy page is not set', 'wp-gdpr-framework');
        }
        
        // Check if privacy dashboard is published on a page
        $found = false;
        $pages = get_posts([
            'post_type' => 'page',
            'post_status' => 'publish',
            'posts_per_page' => -1,
        ]);
        
        foreach ($pages as $page) {
            if (has_shortcode($page->post_content, 'gdpr_privacy_dashboard')) {
                $found = true;
                break;
            }
        }
        
        if (!$found) {
            $issues[] = __('Privacy dashboard shortcode not found on any published page', 'wp-gdpr-framework');
        }
        
        return [
            'compliant' => empty($issues),
            'issues' => $issues
        ];
    }
    
    /**
     * Get compliance statistics
     * 
     * @return array Compliance statistics
     */
    public function getComplianceStatistics() {
        $stats = [
            'consent' => [
                'total_users' => count_users()['total_users'],
                'consented_users' => $this->consent ? $this->consent->getTotalConsents() : 0,
                'consent_percentage' => 0,
                'consent_types' => $this->consent ? $this->consent->getConsentStats()['consent_types'] : []
            ],
            'requests' => [
                'total' => 0,
                'pending' => 0,
                'completed' => 0,
                'failed' => 0,
                'by_type' => []
            ],
            'security' => [
                'last_key_rotation' => get_option('gdpr_last_key_rotation', 0),
                'encryption_enabled' => get_option('gdpr_enable_encryption', 1),
                'tamper_protection' => get_option('gdpr_enable_tamper_protection', 1),
                'ip_anonymization' => get_option('gdpr_anonymize_ip_addresses', 1)
            ],
            'retention' => [
                'last_cleanup' => get_option('gdpr_last_cleanup', 0),
                'next_cleanup' => wp_next_scheduled('gdpr_daily_cleanup')
            ]
        ];
        
        // Calculate consent percentage
        if ($stats['consent']['total_users'] > 0) {
            $stats['consent']['consent_percentage'] = round(
                ($stats['consent']['consented_users'] / $stats['consent']['total_users']) * 100, 
                1
            );
        }
        
        // Get request statistics
        if (isset($this->portability)) {
            global $wpdb;
            $request_table = $wpdb->prefix . 'gdpr_data_requests';
            
            // Get total requests
            $stats['requests']['total'] = $wpdb->get_var("SELECT COUNT(*) FROM $request_table");
            
            // Get requests by status
            $stats['requests']['pending'] = $wpdb->get_var("SELECT COUNT(*) FROM $request_table WHERE status = 'pending'");
            $stats['requests']['completed'] = $wpdb->get_var("SELECT COUNT(*) FROM $request_table WHERE status = 'completed'");
            $stats['requests']['failed'] = $wpdb->get_var("SELECT COUNT(*) FROM $request_table WHERE status = 'failed'");
            
            // Get requests by type
            $request_types = $wpdb->get_results("SELECT request_type, COUNT(*) as count FROM $request_table GROUP BY request_type");
            foreach ($request_types as $type) {
                $stats['requests']['by_type'][$type->request_type] = $type->count;
            }
        }
        
        return $stats;
    }
    
    /**
     * REST API handler for getting compliance status
     */
    public function restGetComplianceStatus() {
        $status = [
            'consent' => $this->checkConsentCompliance(),
            'retention' => $this->checkRetentionCompliance(),
            'security' => $this->checkSecurityCompliance(),
            'rights' => $this->checkRightsCompliance()
        ];
        
        // Calculate overall status
        $status['overall'] = true;
        foreach ($status as $key => $check) {
            if ($key !== 'overall' && !$check['compliant']) {
                $status['overall'] = false;
                break;
            }
        }
        
        return rest_ensure_response($status);
    }
    
    /**
     * REST API handler for getting statistics
     */
    public function restGetStatistics() {
        $stats = $this->getComplianceStatistics();
        return rest_ensure_response($stats);
    }
    
    /**
     * REST API handler for getting system health
     */
    public function restGetSystemHealth() {
        // Get requirements checker component
        $requirements = $this->framework->getComponent('requirements');
        
        if (!$requirements) {
            return rest_ensure_response([
                'error' => __('System requirements checker not initialized', 'wp-gdpr-framework')
            ]);
        }
        
        $health = [
            'requirements' => $requirements->checkAll(),
            'summary' => $requirements->getSummary(),
            'database' => $this->framework->getDatabase()->getTableStatus(),
            'openssl' => [
                'version' => OPENSSL_VERSION_TEXT,
                'recommended' => '1.1.1',
                'compliant' => version_compare(preg_replace('/OpenSSL\s+([\d\.]+)/', '$1', OPENSSL_VERSION_TEXT), '1.1.1', '>=')
            ],
            'php' => [
                'version' => PHP_VERSION,
                'recommended' => '7.4',
                'compliant' => version_compare(PHP_VERSION, '7.4', '>=')
            ],
            'wordpress' => [
                'version' => get_bloginfo('version'),
                'recommended' => '5.8',
                'compliant' => version_compare(get_bloginfo('version'), '5.8', '>=')
            ]
        ];
        
        return rest_ensure_response($health);
    }
    
    /**
     * Render compliance status shortcode
     * 
     * @param array $atts Shortcode attributes
     * @return string Rendered shortcode
     */
    public function renderComplianceStatus($atts = []) {
        $atts = shortcode_atts([
            'show_details' => 'yes'
        ], $atts);
        
        $show_details = $atts['show_details'] === 'yes';
        
        // Check compliance
        $compliance = [
            'consent' => $this->checkConsentCompliance(),
            'retention' => $this->checkRetentionCompliance(),
            'security' => $this->checkSecurityCompliance(),
            'rights' => $this->checkRightsCompliance()
        ];
        
        // Calculate overall compliance
        $overall_compliant = true;
        foreach ($compliance as $check) {
            if (!$check['compliant']) {
                $overall_compliant = false;
                break;
            }
        }
        
        // Start building output
        $output = '<div class="gdpr-compliance-status">';
        
        // Overall status
        $output .= '<div class="gdpr-compliance-overall ' . ($overall_compliant ? 'compliant' : 'non-compliant') . '">';
        $output .= '<h3>' . __('GDPR Compliance Status', 'wp-gdpr-framework') . '</h3>';
        $output .= '<p class="gdpr-status">' . 
                  ($overall_compliant 
                      ? __('Your website appears to be GDPR compliant.', 'wp-gdpr-framework')
                      : __('Your website is not fully GDPR compliant yet.', 'wp-gdpr-framework')) . 
                  '</p>';
        $output .= '</div>';
        
        // Show details if requested
        if ($show_details) {
            $output .= '<div class="gdpr-compliance-details">';
            
            // Consent compliance
            $output .= $this->renderComplianceSection(
                __('Consent Management', 'wp-gdpr-framework'),
                $compliance['consent']['compliant'],
                $compliance['consent']['issues']
            );
            
            // Retention compliance
            $output .= $this->renderComplianceSection(
                __('Data Retention', 'wp-gdpr-framework'),
                $compliance['retention']['compliant'],
                $compliance['retention']['issues']
            );
            
            // Security compliance
            $output .= $this->renderComplianceSection(
                __('Data Security', 'wp-gdpr-framework'),
                $compliance['security']['compliant'],
                $compliance['security']['issues']
            );
            
            // Rights compliance
            $output .= $this->renderComplianceSection(
                __('User Rights', 'wp-gdpr-framework'),
                $compliance['rights']['compliant'],
                $compliance['rights']['issues']
            );
            
            $output .= '</div>';
        }
        
        $output .= '</div>';
        
        return $output;
    }
    
    /**
     * Helper to render compliance section
     * 
     * @param string $title Section title
     * @param bool $compliant Compliance status
     * @param array $issues Compliance issues
     * @return string Rendered section
     */
    private function renderComplianceSection($title, $compliant, $issues) {
        $output = '<div class="gdpr-compliance-section ' . ($compliant ? 'compliant' : 'non-compliant') . '">';
        $output .= '<h4>' . esc_html($title) . '</h4>';
        
        if ($compliant) {
            $output .= '<p class="gdpr-status gdpr-compliant">' . 
                      __('Compliant', 'wp-gdpr-framework') . 
                      '</p>';
        } else {
            $output .= '<p class="gdpr-status gdpr-non-compliant">' . 
                      __('Not compliant', 'wp-gdpr-framework') . 
                      '</p>';
            
            if (!empty($issues)) {
                $output .= '<ul class="gdpr-issues">';
                foreach ($issues as $issue) {
                    $output .= '<li>' . esc_html($issue) . '</li>';
                }
                $output .= '</ul>';
            }
        }
        
        $output .= '</div>';
        return $output;
    }
    
    /**
     * Render user rights summary shortcode
     * 
     * @param array $atts Shortcode attributes
     * @return string Rendered shortcode
     */
    public function renderRightsSummary($atts = []) {
        $atts = shortcode_atts([
            'show_links' => 'yes',
            'dashboard_url' => ''
        ], $atts);
        
        $show_links = $atts['show_links'] === 'yes';
        $dashboard_url = $atts['dashboard_url'];
        
        // Find privacy dashboard page if URL not provided
        if (empty($dashboard_url) && $show_links) {
            $pages = get_posts([
                'post_type' => 'page',
                'post_status' => 'publish',
                'posts_per_page' => 1,
                's' => '[gdpr_privacy_dashboard]'
            ]);
            
            if (!empty($pages)) {
                $dashboard_url = get_permalink($pages[0]->ID);
            }
        }
        
        $output = '<div class="gdpr-rights-summary">';
        $output .= '<h3>' . __('Your GDPR Rights', 'wp-gdpr-framework') . '</h3>';
        $output .= '<p>' . __('Under the General Data Protection Regulation (GDPR), you have several rights regarding your personal data:', 'wp-gdpr-framework') . '</p>';
        
        // Define rights
        $rights = [
            'access' => [
                'title' => __('Right of Access', 'wp-gdpr-framework'),
                'description' => __('You have the right to request a copy of your personal data that we hold.', 'wp-gdpr-framework'),
                'action' => 'export-data'
            ],
            'rectification' => [
                'title' => __('Right to Rectification', 'wp-gdpr-framework'),
                'description' => __('You have the right to request that we correct any inaccurate or incomplete personal data.', 'wp-gdpr-framework'),
                'action' => 'rectify-data'
            ],
            'erasure' => [
                'title' => __('Right to Erasure', 'wp-gdpr-framework'),
                'description' => __('You have the right to request that we delete your personal data in certain circumstances.', 'wp-gdpr-framework'),
                'action' => 'erase-data'
            ],
            'restriction' => [
                'title' => __('Right to Restrict Processing', 'wp-gdpr-framework'),
                'description' => __('You have the right to request that we restrict the processing of your personal data in certain circumstances.', 'wp-gdpr-framework'),
                'action' => 'restrict-processing'
            ],
            'portability' => [
                'title' => __('Right to Data Portability', 'wp-gdpr-framework'),
                'description' => __('You have the right to request that we provide you with your personal data in a structured, commonly used, and machine-readable format.', 'wp-gdpr-framework'),
                'action' => 'export-data'
            ],
            'objection' => [
                'title' => __('Right to Object', 'wp-gdpr-framework'),
                'description' => __('You have the right to object to the processing of your personal data in certain circumstances.', 'wp-gdpr-framework'),
                'action' => 'object-processing'
            ]
        ];
        
        // Render each right
        $output .= '<div class="gdpr-rights-list">';
        foreach ($rights as $key => $right) {
            $output .= '<div class="gdpr-right-item">';
            $output .= '<h4>' . esc_html($right['title']) . '</h4>';
            $output .= '<p>' . esc_html($right['description']) . '</p>';
            
            if ($show_links && !empty($dashboard_url)) {
                $output .= '<p><a href="' . esc_url($dashboard_url . '#' . $right['action']) . '" class="gdpr-right-link">' . 
                          sprintf(__('Exercise your %s right', 'wp-gdpr-framework'), strtolower($right['title'])) . 
                          '</a></p>';
            }
            
            $output .= '</div>';
        }
        $output .= '</div>';
        
        $output .= '</div>';
        
        return $output;
    }
    
    /**
     * Render all-in-one GDPR compliance page shortcode
     * 
     * @param array $atts Shortcode attributes
     * @return string Rendered shortcode
     */
    public function renderAllInOne($atts = []) {
        $atts = shortcode_atts([
            'show_compliance' => 'yes',
            'show_rights' => 'yes',
            'show_dashboard' => 'yes',
            'show_consent' => 'yes'
        ], $atts);
        
        $output = '<div class="gdpr-all-in-one">';
        
        // Compliance status
        if ($atts['show_compliance'] === 'yes') {
            $output .= $this->renderComplianceStatus(['show_details' => 'yes']);
        }
        
        // Rights summary
        if ($atts['show_rights'] === 'yes') {
            $output .= $this->renderRightsSummary(['show_links' => 'yes']);
        }
        
        // Privacy dashboard
        if ($atts['show_dashboard'] === 'yes' && is_user_logged_in()) {
            // Check if portability component is available
            if (isset($this->portability) && method_exists($this->portability, 'renderPrivacyDashboard')) {
                $output .= $this->portability->renderPrivacyDashboard();
            } else {
                $output .= '<div class="gdpr-notice gdpr-error">' . 
                          __('Privacy dashboard component not available.', 'wp-gdpr-framework') . 
                          '</div>';
            }
        } elseif ($atts['show_dashboard'] === 'yes') {
            $output .= '<div class="gdpr-login-prompt">';
            $output .= '<p>' . __('Please log in to access your privacy dashboard.', 'wp-gdpr-framework') . '</p>';
            $output .= '<p><a href="' . esc_url(wp_login_url(get_permalink())) . '" class="button">' . 
                      __('Log In', 'wp-gdpr-framework') . 
                      '</a></p>';
            $output .= '</div>';
        }
        
        // Consent form
        if ($atts['show_consent'] === 'yes' && isset($this->consent) && method_exists($this->consent, 'renderConsentForm')) {
            $output .= $this->consent->renderConsentForm();
        }
        
        $output .= '</div>';
        
        return $output;
    }
    
    /**
     * Check if user has given consent for a specific type
     * 
     * @param string $type Consent type key
     * @param int|null $user_id User ID (defaults to current user)
     * @return bool Whether user has given consent
     */
    public function hasConsent($type, $user_id = null) {
        if (!isset($this->consent) || !method_exists($this->consent, 'hasConsent')) {
            return false;
        }
        
        return $this->consent->hasConsent($type, $user_id);
    }
    
    /**
     * Store encrypted user data
     * 
     * @param int $user_id User ID
     * @param string $data_type Data type identifier
     * @param mixed $data Data to encrypt and store
     * @return bool Whether data was stored successfully
     */
    public function storeUserData($user_id, $data_type, $data) {
        if (!isset($this->encryption) || !method_exists($this->encryption, 'encrypt')) {
            return false;
        }
        
        // Encrypt the data
        $encrypted_data = $this->encryption->encrypt($data);
        
        // Get active key ID
        $key_id = $this->encryption->getActiveKeyId();
        
        // Store in database
        global $wpdb;
        $table = $wpdb->prefix . 'gdpr_user_data';
        
        // Check if data already exists
        $existing = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM $table WHERE user_id = %d AND data_type = %s",
            $user_id,
            $data_type
        ));
        
        if ($existing) {
            // Update existing data
            $result = $wpdb->update(
                $table,
                [
                    'encrypted_data' => $encrypted_data,
                    'key_id' => $key_id,
                    'updated_at' => current_time('mysql')
                ],
                [
                    'id' => $existing
                ],
                ['%s', '%s', '%s'],
                ['%d']
            );
        } else {
            // Insert new data
            $result = $wpdb->insert(
                $table,
                [
                    'user_id' => $user_id,
                    'data_type' => $data_type,
                    'encrypted_data' => $encrypted_data,
                    'key_id' => $key_id,
                    'created_at' => current_time('mysql'),
                    'updated_at' => current_time('mysql')
                ],
                ['%d', '%s', '%s', '%s', '%s', '%s']
            );
        }
        
        // Log the activity
        if ($result && isset($this->audit)) {
            $this->audit->logEvent(
                'user_data_stored',
                get_current_user_id(),
                [
                    'user_id' => $user_id,
                    'data_type' => $data_type
                ],
                'medium'
            );
        }
        
        return (bool) $result;
    }
    
    /**
     * Retrieve encrypted user data
     * 
     * @param int $user_id User ID
     * @param string $data_type Data type identifier
     * @return mixed|false Decrypted data or false on failure
     */
    public function getUserData($user_id, $data_type) {
        if (!isset($this->encryption) || !method_exists($this->encryption, 'decrypt')) {
            return false;
        }
        
        global $wpdb;
        $table = $wpdb->prefix . 'gdpr_user_data';
        
        // Get encrypted data
        $data = $wpdb->get_row($wpdb->prepare(
            "SELECT encrypted_data, key_id FROM $table WHERE user_id = %d AND data_type = %s",
            $user_id,
            $data_type
        ));
        
        if (!$data) {
            return false;
        }
        
        // Decrypt the data
        $decrypted = $this->encryption->decrypt($data->encrypted_data, $data->key_id);
        
        // Log the access
        if (isset($this->audit)) {
            $this->audit->logEvent(
                'user_data_accessed',
                get_current_user_id(),
                [
                    'user_id' => $user_id,
                    'data_type' => $data_type
                ],
                'medium'
            );
        }
        
        return $decrypted;
    }
    
    /**
     * Delete user data
     * 
     * @param int $user_id User ID
     * @param string|null $data_type Optional data type to delete (null for all)
     * @return bool Whether data was deleted successfully
     */
    public function deleteUserData($user_id, $data_type = null) {
        global $wpdb;
        $table = $wpdb->prefix . 'gdpr_user_data';
        
        if ($data_type === null) {
            // Delete all data for user
            $result = $wpdb->delete(
                $table,
                ['user_id' => $user_id],
                ['%d']
            );
        } else {
            // Delete specific data type
            $result = $wpdb->delete(
                $table,
                [
                    'user_id' => $user_id,
                    'data_type' => $data_type
                ],
                ['%d', '%s']
            );
        }
        
        // Log the deletion
        if ($result && isset($this->audit)) {
            $this->audit->logEvent(
                'user_data_deleted',
                get_current_user_id(),
                [
                    'user_id' => $user_id,
                    'data_type' => $data_type ?? 'all'
                ],
                'medium'
            );
        }
        
        return (bool) $result;
    }
    
    /**
     * Anonymize IP address according to settings
     * 
     * @param string $ip IP address to anonymize
     * @return string Anonymized IP address
     */
    public function anonymizeIP($ip) {
        if (empty($ip)) {
            return '';
        }
        
        // Check if IP anonymization is enabled
        if (!get_option('gdpr_anonymize_ip_addresses', true)) {
            return $ip;
        }
        
        // Get anonymization method
        $method = get_option('gdpr_ip_anonymization_method', 'partial');
        
        switch ($method) {
            case 'full':
                // Full anonymization (replace with 0.0.0.0 or ::)
                return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? '::' : '0.0.0.0';
                
            case 'hash':
                // Hash the IP with salt
                $salt = get_option('gdpr_audit_integrity_salt', wp_salt('auth'));
                return hash('sha512', $ip . $salt);
                
            case 'partial':
            default:
                // Partial anonymization (last octet/group)
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    // For IPv4, replace the last octet with zero
                    return preg_replace('/\.\d+$/', '.0', $ip);
                } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                    // For IPv6, keep first 3 parts and zero the rest
                    $parts = explode(':', $ip);
                    return count($parts) >= 4 
                        ? $parts[0] . ':' . $parts[1] . ':' . $parts[2] . ':0:0:0:0:0'
                        : $ip;
                }
                return $ip;
        }
    }
    
    /**
     * Log GDPR-related event
     * 
     * @param string $action Action name
     * @param array $details Action details
     * @param string $severity Severity level (low, medium, high)
     * @return bool Whether event was logged successfully
     */
    public function logEvent($action, $details = [], $severity = 'medium') {
        if (!isset($this->audit) || !method_exists($this->audit, 'logEvent')) {
            return false;
        }
        
        return $this->audit->logEvent(
            $action,
            get_current_user_id(),
            $details,
            $severity
        );
    }
    
    /**
     * Check if a plugin integration is active
     * 
     * @param string $plugin Plugin slug
     * @return bool Whether integration is active
     */
    public function isIntegrationActive($plugin) {
        switch ($plugin) {
            case 'woocommerce':
                return class_exists('WooCommerce');
                
            case 'contact-form-7':
                return defined('WPCF7_VERSION');
                
            case 'gravity-forms':
                return class_exists('GFForms');
                
            default:
                return apply_filters('gdpr_is_integration_active', false, $plugin);
        }
    }
    
    /**
     * Get the path to a GDPR framework template
     * 
     * @param string $template Template name
     * @return string Template path
     */
    public function getTemplatePath($template) {
        // Check if template exists in theme
        $theme_template = locate_template('gdpr-framework/' . $template . '.php');
        
        if ($theme_template) {
            return $theme_template;
        }
        
        // Return default template
        return GDPR_FRAMEWORK_TEMPLATE_PATH . $template . '.php';
    }
    
    /**
     * Get available export formats
     * 
     * @return array Export formats
     */
    public function getExportFormats() {
        return get_option('gdpr_export_formats', ['json', 'xml', 'csv']);
    }
    
    /**
     * Check if consent version needs renewal
     * 
     * @param int $user_id User ID
     * @return bool Whether consent needs renewal
     */
    public function needsConsentRenewal($user_id) {
        if (!isset($this->consent) || !method_exists($this->consent, 'getUserConsentVersion')) {
            return false;
        }
        
        $user_version = $this->consent->getUserConsentVersion($user_id);
        $current_version = $this->consent->getCurrentConsentVersion();
        
        return ($user_version !== $current_version);
    }
    
    /**
     * Get all user GDPR-related data
     * 
     * @param int $user_id User ID
     * @return array User data
     */
    public function getAllUserData($user_id) {
        $data = [
            'user_info' => [],
            'consents' => [],
            'data_requests' => [],
            'custom_data' => []
        ];
        
        // Get user info
        $user = get_userdata($user_id);
        if ($user) {
            $data['user_info'] = [
                'id' => $user->ID,
                'username' => $user->user_login,
                'email' => $user->user_email,
                'display_name' => $user->display_name,
                'registered_date' => $user->user_registered
            ];
        }
        
        // Get consent history
        if (isset($this->consent) && method_exists($this->consent, 'getConsentHistory')) {
            $data['consents'] = $this->consent->getConsentHistory($user_id);
        }
        
        // Get data requests
        if (isset($this->portability)) {
            global $wpdb;
            $request_table = $wpdb->prefix . 'gdpr_data_requests';
            
            $data['data_requests'] = $wpdb->get_results($wpdb->prepare(
                "SELECT * FROM $request_table WHERE user_id = %d ORDER BY created_at DESC",
                $user_id
            ));
        }
        
        // Get custom data
        global $wpdb;
        $data_table = $wpdb->prefix . 'gdpr_user_data';
        
        $custom_data_types = $wpdb->get_results($wpdb->prepare(
            "SELECT id, data_type, created_at, updated_at FROM $data_table WHERE user_id = %d",
            $user_id
        ));
        
        foreach ($custom_data_types as $item) {
            $data['custom_data'][] = [
                'id' => $item->id,
                'type' => $item->data_type,
                'created_at' => $item->created_at,
                'updated_at' => $item->updated_at,
                'data' => $this->getUserData($user_id, $item->data_type)
            ];
        }
        
        // Allow plugins to add their own data
        $data = apply_filters('gdpr_get_all_user_data', $data, $user_id);
        
        return $data;
    }
}