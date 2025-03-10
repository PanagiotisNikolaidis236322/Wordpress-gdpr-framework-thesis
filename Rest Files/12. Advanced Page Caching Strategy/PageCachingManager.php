<?php
namespace GDPRFramework\Components;

/**
 * Page Caching Manager
 * 
 * Implements full-page caching for GDPR content as specified in Appendix A
 * - Handles caching of static GDPR content
 * - Excludes sensitive content from cache
 * - Integrates with common caching solutions
 */
class PageCachingManager {
    private $settings;
    private $object_cache;
    private $is_enabled = false;
    private $cache_dir;
    private $cache_expiry = 3600; // 1 hour default
    private $debug = false;
    
    // GDPR pages that should never be cached
    private $no_cache_pages = [
        'privacy-dashboard',
        'data-request',
        'consent-management'
    ];
    
    // List of supported caching plugins
    private $supported_plugins = [
        'wp-rocket' => 'WP Rocket',
        'w3-total-cache' => 'W3 Total Cache',
        'wp-super-cache' => 'WP Super Cache',
        'litespeed-cache' => 'LiteSpeed Cache',
        'autoptimize' => 'Autoptimize'
    ];
    
    // Detected caching plugins
    private $detected_plugins = [];

    public function __construct($settings, $object_cache = null) {
        $this->settings = $settings;
        $this->object_cache = $object_cache;
        $this->debug = defined('WP_DEBUG') && WP_DEBUG;
        
        // Set up cache directory
        $upload_dir = wp_upload_dir();
        $this->cache_dir = $upload_dir['basedir'] . '/gdpr-page-cache';
        
        // Check if page caching is enabled
        $this->is_enabled = get_option('gdpr_enable_page_caching', 0);
        $this->cache_expiry = get_option('gdpr_page_cache_expiry', 3600);
        
        // Detect installed caching plugins
        $this->detectCachingPlugins();
        
        // Register hooks
        add_action('admin_init', [$this, 'registerSettings']);
        add_action('template_redirect', [$this, 'initPageCaching'], 5);
        add_action('gdpr_consent_updated', [$this, 'clearUserCache'], 10, 3);
        add_action('gdpr_data_exported', [$this, 'clearUserCache'], 10, 2);
        add_action('gdpr_data_erased', [$this, 'clearUserCache'], 10, 2);
        
        // Integrate with caching plugins
        $this->initCachingPluginIntegrations();
    }
    
    /**
     * Register page caching settings
     */
    public function registerSettings() {
        register_setting('gdpr_framework_settings', 'gdpr_enable_page_caching', [
            'type' => 'boolean',
            'default' => 0,
            'sanitize_callback' => 'absint'
        ]);
        
        register_setting('gdpr_framework_settings', 'gdpr_page_cache_expiry', [
            'type' => 'integer',
            'default' => 3600,
            'sanitize_callback' => [$this, 'sanitizeCacheExpiry']
        ]);
        
        register_setting('gdpr_framework_settings', 'gdpr_cache_exceptions', [
            'type' => 'string',
            'default' => implode("\n", $this->no_cache_pages),
            'sanitize_callback' => 'sanitize_textarea_field'
        ]);
        
        // Register settings section and fields
        add_settings_section(
            'gdpr_page_caching_section',
            __('Page Caching', 'wp-gdpr-framework'),
            [$this, 'renderPageCachingSection'],
            'gdpr_framework_settings'
        );
        
        add_settings_field(
            'gdpr_enable_page_caching',
            __('Enable Page Caching', 'wp-gdpr-framework'),
            [$this, 'renderEnablePageCachingField'],
            'gdpr_framework_settings',
            'gdpr_page_caching_section'
        );
        
        add_settings_field(
            'gdpr_page_cache_expiry',
            __('Page Cache Expiration', 'wp-gdpr-framework'),
            [$this, 'renderPageCacheExpiryField'],
            'gdpr_framework_settings',
            'gdpr_page_caching_section'
        );
        
        add_settings_field(
            'gdpr_cache_exceptions',
            __('Cache Exceptions', 'wp-gdpr-framework'),
            [$this, 'renderCacheExceptionsField'],
            'gdpr_framework_settings',
            'gdpr_page_caching_section'
        );
    }
    
    /**
     * Render page caching section description
     */
    public function renderPageCachingSection() {
        echo '<p>' . esc_html__('Configure page caching settings for GDPR content.', 'wp-gdpr-framework') . '</p>';
        
        // Show detected caching plugins
        if (!empty($this->detected_plugins)) {
            echo '<div class="notice notice-info inline">';
            echo '<p><strong>' . esc_html__('Detected caching plugins:', 'wp-gdpr-framework') . '</strong> ';
            echo esc_html(implode(', ', $this->detected_plugins));
            echo '</p>';
            echo '</div>';
        }
    }
    
    /**
     * Render enable page caching field
     */
    public function renderEnablePageCachingField() {
        $enabled = get_option('gdpr_enable_page_caching', 0);
        
        echo '<input type="checkbox" id="gdpr_enable_page_caching" name="gdpr_enable_page_caching" value="1" ' . 
             checked($enabled, 1, false) . '>';
             
        echo '<p class="description">' . 
             esc_html__('Enable page caching for static GDPR content.', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Render page cache expiry field
     */
    public function renderPageCacheExpiryField() {
        $expiry = get_option('gdpr_page_cache_expiry', 3600);
        
        echo '<input type="number" id="gdpr_page_cache_expiry" name="gdpr_page_cache_expiry" value="' . 
             esc_attr($expiry) . '" min="300" max="86400" step="300" class="medium-text"> ' . 
             esc_html__('seconds', 'wp-gdpr-framework');
             
        echo '<p class="description">' . 
             esc_html__('How long to cache static GDPR pages (300-86400 seconds).', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Render cache exceptions field
     */
    public function renderCacheExceptionsField() {
        $exceptions = get_option('gdpr_cache_exceptions', implode("\n", $this->no_cache_pages));
        
        echo '<textarea id="gdpr_cache_exceptions" name="gdpr_cache_exceptions" rows="5" cols="50" class="large-text">' . 
             esc_textarea($exceptions) . '</textarea>';
             
        echo '<p class="description">' . 
             esc_html__('Enter URL slugs that should never be cached (one per line).', 'wp-gdpr-framework') . 
             '<br>' . 
             esc_html__('Example: privacy-dashboard', 'wp-gdpr-framework') . 
             '</p>';
    }
    
    /**
     * Sanitize cache expiry setting
     */
    public function sanitizeCacheExpiry($value) {
        $value = absint($value);
        
        if ($value < 300) {
            return 300; // Minimum 5 minutes
        }
        
        if ($value > 86400) {
            return 86400; // Maximum 1 day
        }
        
        return $value;
    }
    
    /**
     * Initialize page caching
     */
    public function initPageCaching() {
        // Skip if caching is disabled
        if (!$this->is_enabled) {
            return;
        }
        
        // Skip if user is logged in
        if (is_user_logged_in()) {
            $this->addNoCacheHeaders();
            return;
        }
        
        // Skip if on a non-cacheable page
        if ($this->isNoCachePage()) {
            $this->addNoCacheHeaders();
            return;
        }
        
        // Check if this is a GDPR-related page
        if ($this->isGDPRPage()) {
            // If we have a cached version, serve it
            $cache_key = $this->generatePageCacheKey();
            $cached_content = $this->getPageCache($cache_key);
            
            if ($cached_content !== false) {
                echo $cached_content;
                exit;
            }
            
            // Otherwise, start output buffering to cache the page
            ob_start([$this, 'cachePageOutput']);
        }
    }
    
    /**
     * Cache page output callback
     */
    public function cachePageOutput($content) {
        if (empty($content)) {
            return $content;
        }
        
        // Don't cache error pages
        if (http_response_code() !== 200) {
            return $content;
        }
        
        // Don't cache if headers indicate no caching
        $headers = headers_list();
        foreach ($headers as $header) {
            if (stripos($header, 'Cache-Control: no-cache') !== false || 
                stripos($header, 'Cache-Control: no-store') !== false) {
                return $content;
            }
        }
        
        // Generate cache key
        $cache_key = $this->generatePageCacheKey();
        
        // Store the content in cache
        $this->setPageCache($cache_key, $content);
        
        // Add cache info comment
        $content .= "\n<!-- Page cached by GDPR Framework on " . date('Y-m-d H:i:s') . " -->";
        
        return $content;
    }
    
    /**
     * Generate a cache key for the current page
     */
    private function generatePageCacheKey() {
        $url = $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        
        // Add query string if present (excluding some parameters)
        if (!empty($_SERVER['QUERY_STRING'])) {
            $excluded_params = ['nocache', 'gdpr_flush'];
            parse_str($_SERVER['QUERY_STRING'], $params);
            
            foreach ($excluded_params as $excluded) {
                unset($params[$excluded]);
            }
            
            if (!empty($params)) {
                $url .= '?' . http_build_query($params);
            }
        }
        
        // Add mobile detection
        $is_mobile = wp_is_mobile();
        $device = $is_mobile ? 'mobile' : 'desktop';
        
        return 'gdpr_page_' . md5($url . $device);
    }
    
    /**
     * Get cached page content
     */
    private function getPageCache($key) {
        // First check object cache if available
        if ($this->object_cache && $this->object_cache->get($key)) {
            return $this->object_cache->get($key);
        }
        
        // Otherwise check file cache
        $cache_file = $this->getCacheFilePath($key);
        
        if (file_exists($cache_file)) {
            $cached_data = file_get_contents($cache_file);
            
            if ($cached_data) {
                // Check if cache has expired
                $modified_time = filemtime($cache_file);
                
                if (time() - $modified_time > $this->cache_expiry) {
                    // Cache expired, delete the file
                    @unlink($cache_file);
                    return false;
                }
                
                return $cached_data;
            }
        }
        
        return false;
    }
    
    /**
     * Set page cache content
     */
    private function setPageCache($key, $content) {
        // Store in object cache if available
        if ($this->object_cache) {
            $this->object_cache->set($key, $content, $this->cache_expiry);
        }
        
        // Also store in file cache
        $cache_file = $this->getCacheFilePath($key);
        
        // Create directory if it doesn't exist
        if (!file_exists(dirname($cache_file))) {
            wp_mkdir_p(dirname($cache_file));
        }
        
        // Write content to file
        file_put_contents($cache_file, $content);
    }
    
    /**
     * Get the file path for a cache key
     */
    private function getCacheFilePath($key) {
        // Create subdirectories based on first few chars of key
        $hash = md5($key);
        $subdir = substr($hash, 0, 2) . '/' . substr($hash, 2, 2);
        $dir = $this->cache_dir . '/' . $subdir;
        
        // Create directory if it doesn't exist
        if (!file_exists($dir)) {
            wp_mkdir_p($dir);
            
            // Add index.php to prevent directory listing
            file_put_contents($dir . '/index.php', '<?php // Silence is golden');
        }
        
        return $dir . '/' . $key . '.html';
    }
    
    /**
     * Check if current page is a GDPR-related page
     */
    private function isGDPRPage() {
        global $post;
        
        // If not on a post or page, it's not a GDPR page
        if (!is_singular() || !$post) {
            return false;
        }
        
        // Check for GDPR shortcodes
        $gdpr_shortcodes = [
            'gdpr_privacy_dashboard',
            'gdpr_consent_form',
            'gdpr_audit_log'
        ];
        
        foreach ($gdpr_shortcodes as $shortcode) {
            if (has_shortcode($post->post_content, $shortcode)) {
                return true;
            }
        }
        
        // Check for privacy policy page
        $privacy_page_id = get_option('wp_page_for_privacy_policy');
        if ($privacy_page_id && $post->ID == $privacy_page_id) {
            return true;
        }
        
        // Check for GDPR settings page
        $gdpr_page_id = get_option('gdpr_privacy_policy_page');
        if ($gdpr_page_id && $post->ID == $gdpr_page_id) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if current page should not be cached
     */
    private function isNoCachePage() {
        global $post;
        
        // If not on a post or page, don't apply no-cache rules
        if (!is_singular() || !$post) {
            return false;
        }
        
        // Get the current slug
        $slug = $post->post_name;
        
        // Get exceptions from settings
        $exceptions = get_option('gdpr_cache_exceptions', implode("\n", $this->no_cache_pages));
        $exception_list = array_map('trim', explode("\n", $exceptions));
        
        // Check if current slug is in exceptions
        if (in_array($slug, $exception_list)) {
            return true;
        }
        
        // Check query parameters
        if (isset($_GET['nocache']) || isset($_GET['gdpr_flush'])) {
            return true;
        }
        
        // Check if this is a form submission
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            return true;
        }
        
        return false;
    }
    
    /**
     * Add no-cache headers to response
     */
    private function addNoCacheHeaders() {
        if (!headers_sent()) {
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            header('Pragma: no-cache');
            header('Expires: Sat, 26 Jul 1997 05:00:00 GMT'); // Date in the past
        }
    }
    
    /**
     * Clear cache for a specific user
     */
    public function clearUserCache($user_id) {
        // This is a simplified version - in reality, we can't easily target
        // specific user's cached pages, so we clear all GDPR-related caches
        $this->clearAllPageCache();
    }
    
    /**
     * Clear all page cache
     */
    public function clearAllPageCache() {
        // Clear object cache if available
        if ($this->object_cache) {
            // Clear all keys starting with 'gdpr_page_'
            // Since we can't easily enumerate keys in most object cache implementations,
            // we'll rely on the file cache cleanup
        }
        
        // Clear file cache
        $this->recursiveRmdir($this->cache_dir);
        
        // Recreate cache directory
        if (!file_exists($this->cache_dir)) {
            wp_mkdir_p($this->cache_dir);
            file_put_contents($this->cache_dir . '/index.php', '<?php // Silence is golden');
        }
        
        // Integrate with other caching plugins
        $this->clearCachingPlugins();
    }
    
    /**
     * Recursively remove a directory
     */
    private function recursiveRmdir($dir) {
        if (!is_dir($dir)) {
            return;
        }
        
        $files = array_diff(scandir($dir), ['.', '..']);
        
        foreach ($files as $file) {
            $path = $dir . '/' . $file;
            
            if (is_dir($path)) {
                $this->recursiveRmdir($path);
            } else {
                @unlink($path);
            }
        }
        
        @rmdir($dir);
    }
    
    /**
     * Detect installed caching plugins
     */
    private function detectCachingPlugins() {
        $active_plugins = (array) get_option('active_plugins', []);
        
        foreach ($this->supported_plugins as $plugin_file => $plugin_name) {
            // Check if plugin is active
            foreach ($active_plugins as $active_plugin) {
                if (strpos($active_plugin, $plugin_file) !== false) {
                    $this->detected_plugins[$plugin_file] = $plugin_name;
                    break;
                }
            }
        }
    }
    
    /**
     * Initialize integrations with cache plugins
     */
    private function initCachingPluginIntegrations() {
        // Skip if no caching plugins are detected
        if (empty($this->detected_plugins)) {
            return;
        }
        
        // WP Rocket integration
        if (isset($this->detected_plugins['wp-rocket'])) {
            add_filter('rocket_cache_reject_uri', [$this, 'wpRocketExcludeURIs']);
            add_filter('rocket_cache_reject_cookies', [$this, 'wpRocketExcludeCookies']);
            add_action('gdpr_consent_updated', [$this, 'wpRocketClearCache'], 10, 3);
        }
        
        // W3 Total Cache integration
        if (isset($this->detected_plugins['w3-total-cache']) && function_exists('w3tc_flush_all')) {
            add_action('gdpr_consent_updated', [$this, 'w3tcClearCache'], 10, 3);
        }
        
        // WP Super Cache integration
        if (isset($this->detected_plugins['wp-super-cache']) && function_exists('wp_cache_clear_cache')) {
            add_action('gdpr_consent_updated', [$this, 'wpscClearCache'], 10, 3);
        }
        
        // LiteSpeed Cache integration
        if (isset($this->detected_plugins['litespeed-cache']) && class_exists('LiteSpeed\Purge')) {
            add_action('gdpr_consent_updated', [$this, 'litespeedClearCache'], 10, 3);
        }
    }
    
    /**
     * WP Rocket: Exclude GDPR URIs from caching
     */
    public function wpRocketExcludeURIs($uris) {
        $exceptions = get_option('gdpr_cache_exceptions', implode("\n", $this->no_cache_pages));
        $exception_list = array_map('trim', explode("\n", $exceptions));
        
        foreach ($exception_list as $exception) {
            $uris[] = '/(.+/)?' . $exception . '/?';
        }
        
        return $uris;
    }
    
    /**
     * WP Rocket: Exclude cookies
     */
    public function wpRocketExcludeCookies($cookies) {
        $cookies[] = 'gdpr_consent_';
        $cookies[] = 'gdpr_privacy_';
        return $cookies;
    }
    
    /**
     * WP Rocket: Clear cache on consent update
     */
    public function wpRocketClearCache() {
        if (function_exists('rocket_clean_domain')) {
            rocket_clean_domain();
        }
    }
    
    /**
     * W3 Total Cache: Clear cache
     */
    public function w3tcClearCache() {
        if (function_exists('w3tc_flush_all')) {
            w3tc_flush_all();
        }
    }
    
    /**
     * WP Super Cache: Clear cache
     */
    public function wpscClearCache() {
        if (function_exists('wp_cache_clear_cache')) {
            wp_cache_clear_cache();
        }
    }
    
    /**
     * LiteSpeed Cache: Clear cache
     */
    public function litespeedClearCache() {
        if (class_exists('LiteSpeed\Purge')) {
            \LiteSpeed\Purge::purge_all();
        }
    }
    
    /**
     * Get caching status and statistics
     */
    public function getCachingStats() {
        // Count cached files
        $cached_files = $this->countCachedFiles($this->cache_dir);
        
        return [
            'enabled' => $this->is_enabled,
            'cache_dir' => $this->cache_dir,
            'cache_expiry' => $this->cache_expiry,
            'cached_files' => $cached_files,
            'cache_size' => $this->getCacheSize($this->cache_dir),
            'detected_plugins' => $this->detected_plugins,
            'exceptions' => array_map('trim', explode("\n", get_option('gdpr_cache_exceptions', implode("\n", $this->no_cache_pages))))
        ];
    }
    
    /**
     * Count cached files
     */
    private function countCachedFiles($dir) {
        if (!is_dir($dir)) {
            return 0;
        }
        
        $count = 0;
        $files = array_diff(scandir($dir), ['.', '..']);
        
        foreach ($files as $file) {
            $path = $dir . '/' . $file;
            
            if (is_dir($path)) {
                $count += $this->countCachedFiles($path);
            } elseif (pathinfo($path, PATHINFO_EXTENSION) === 'html') {
                $count++;
            }
        }
        
        return $count;
    }
    
    /**
     * Get cache size
     */
    private function getCacheSize($dir) {
        if (!is_dir($dir)) {
            return '0 B';
        }
        
        $size = 0;
        $files = array_diff(scandir($dir), ['.', '..']);
        
        foreach ($files as $file) {
            $path = $dir . '/' . $file;
            
            if (is_dir($path)) {
                $size += $this->getCacheSizeInBytes($path);
            } elseif (pathinfo($path, PATHINFO_EXTENSION) === 'html') {
                $size += filesize($path);
            }
        }
        
        return $this->formatBytes($size);
    }
    
    /**
     * Get cache size in bytes
     */
    private function getCacheSizeInBytes($dir) {
        if (!is_dir($dir)) {
            return 0;
        }
        
        $size = 0;
        $files = array_diff(scandir($dir), ['.', '..']);
        
        foreach ($files as $file) {
            $path = $dir . '/' . $file;
            
            if (is_dir($path)) {
                $size += $this->getCacheSizeInBytes($path);
            } else {
                $size += filesize($path);
            }
        }
        
        return $size;
    }
    
    /**
     * Format bytes to human-readable format
     */
    private function formatBytes($bytes, $precision = 2) {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        
        $bytes /= (1 << (10 * $pow));
        
        return round($bytes, $precision) . ' ' . $units[$pow];
    }
}