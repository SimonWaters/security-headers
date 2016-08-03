<?php
/**
 * Plugin Name: HTTP Headers
 * Plugin URI: http://surevine.com/
 * Description: Sets security related headers (HSTS etc)
 * Version: 0.7
 * Author: Simon Waters (Surevine Ltd)
 * Author URI: http://waters.me/
 * License: GPL2 or any later version
 */

function security_headers_insert() {
    if ( headers_sent() ) {
        error_log("Headers already sent HTTP Headers modules unable to function");
    }

    // HSTS
    if (is_ssl()){
      $time = esc_attr(get_option('security_headers_hsts_time'));
      $subdomain = esc_attr(get_option('security_headers_hsts_subdomains'));
      $preload = esc_attr(get_option('security_headers_hsts_preload'));
      if ( ctype_digit($time)  ) {
	$subdomain_output = $subdomain > 0 ? "; includeSubDomains" : "";
        $preload_output = $preload > 0 ? "; preload" : "";
        header("Strict-Transport-Security: max-age=$time $subdomain_output $preload_output");
      }
    }

    // No Sniff
    $nosniff = esc_attr(get_option('security_headers_nosniff'));
    if ($nosniff == 1) {
        send_nosniff_header();
    }

    // XSS
    $xss = esc_attr(get_option('security_headers_xss'));
    if ($xss == 1) {
        header("X-XSS-Protection: 1; mode=block;");
    }

    // Frame Options
    $frame = esc_attr(get_option('security_headers_frame'));
    if ($frame == 1) {
        send_frame_options_header();
    }

    // HPKP
    if (is_ssl()){
      $pinkey1 = esc_attr(get_option('security_headers_hpkp_key1'));
      $pinkey2 = esc_attr(get_option('security_headers_hpkp_key2'));
      $pinkey3 = esc_attr(get_option('security_headers_hpkp_key3'));
      $pintime = esc_attr(get_option('security_headers_hpkp_time'));
      $pinsubdomain = esc_attr(get_option('security_headers_hpkp_subdomains'));
      $pinuri = get_option('security_headers_hpkp_uri');
      // Standard requires at least one backup key so insist on two keys before working
      if ( is_numeric($pintime) && !empty($pinkey1) && !empty($pinkey2)) {
        $pinheader="Public-Key-Pins: ";
        $pinheader .= 'pin-sha256="'. $pinkey1 .'";';
        $pinheader .= 'pin-sha256="'. $pinkey2 .'";';
        if (!empty($pinkey3)) { $pinheader .= 'pin-sha256="'. $pinkey3 .'";'; }
	$pinheader .= " max-age=$pintime;";
        if ($pinsubdomain > 0) { $pinheader .= ' includeSubDomains;'; } 
        if (!empty($pinuri)) { $pinheader .= ' report-uri="'. $pinuri .'";'; }
        header($pinheader);
      }
    }

}
add_action('send_headers', 'security_headers_insert');
// admin section doesn't have a send_headers action so we abuse init
// https://codex.wordpress.org/Plugin_API/Action_Reference
add_action('admin_init', 'security_headers_insert');

function security_headers_activate() {
    register_setting('security_group', 'security_headers_hsts_time', 'istime');
    register_setting('security_group', 'security_headers_hsts_subdomains', 'ischecked');
    register_setting('security_group', 'security_headers_hsts_preload', 'ischecked');
    register_setting('security_group', 'security_headers_nosniff', 'ischecked');
    register_setting('security_group', 'security_headers_xss', 'ischecked');
    register_setting('security_group', 'security_headers_frame', 'ischecked');
    register_setting('security_group', 'security_headers_hpkp_key1', 'iskey');
    register_setting('security_group', 'security_headers_hpkp_key2', 'iskey');
    register_setting('security_group', 'security_headers_hpkp_key3', 'iskey');
    register_setting('security_group', 'security_headers_hpkp_time', 'istime');
    register_setting('security_group', 'security_headers_hpkp_subdomains', 'ischecked');
    register_setting('security_group', 'security_headers_hpkp_uri', 'isuri');
}

register_activation_hook(__FILE__, 'security_headers_activate');

function security_headers_deactivate() {
    remove_action('admin_menu', 'security_headers_settings');
    remove_action('send_headers', 'security_headers');
    remove_action('admin_init', 'security_headers');

    unregister_setting('security_group', 'security_headers_hsts_time', 'istime');
    unregister_setting('security_group', 'security_headers_hsts_subdomains', 'ischecked');
    unregister_setting('security_group', 'security_headers_hsts_preload', 'ischecked');
    unregister_setting('security_group', 'security_headers_nosniff', 'ischecked');
    unregister_setting('security_group', 'security_headers_xss', 'ischecked');
    unregister_setting('security_group', 'security_headers_frame', 'ischecked');
    unregister_setting('security_group', 'security_headers_hpkp_key1', 'iskey');
    unregister_setting('security_group', 'security_headers_hpkp_key2', 'iskey');
    unregister_setting('security_group', 'security_headers_hpkp_key3', 'iskey');
    unregister_setting('security_group', 'security_headers_hpkp_time', 'istime');
    unregister_setting('security_group', 'security_headers_hpkp_subdomains', 'ischecked');
    unregister_setting('security_group', 'security_headers_hpkp_uri', 'isuri');

}
register_deactivation_hook(__FILE__, 'security_headers_deactivate');

function security_headers_display_form() {
    echo '<div class="wrap">';
    echo '<h1>Options for HTTP Headers</h1>';
    echo '<form action="options.php" method="POST">';
    settings_fields('security_group');
    do_settings_sections('security_headers');
    submit_button();
    echo '</form>';
    echo '</div>';
}

function security_headers_settings() {
    add_options_page('HTTP Headers', 'HTTP Headers', 'manage_options', 'security_headers', 'security_headers_display_form');
    add_settings_section('section_HEAD', 'General Security Headers', 'section_HEAD_callback', 'security_headers');
    add_settings_field( 'field_HSTS_nosniff', 'Disable content sniffing', 'field_HSTS_nosniff_callback', 'security_headers', 'section_HEAD');
    add_settings_field( 'field_HSTS_xss', 'Enable Chrome XSS protection', 'field_HSTS_xss_callback', 'security_headers', 'section_HEAD');
    add_settings_field( 'field_HSTS_frame', 'Restrict framing of main site', 'field_HSTS_frame_callback', 'security_headers', 'section_HEAD');
    add_settings_section('section_HSTS', 'HTTPS Strict Transport Security', 'section_HSTS_callback', 'security_headers');
    add_settings_field( 'field_HSTS_time', 'HSTS Time to live (seconds)', 'field_HSTS_time_callback', 'security_headers', 'section_HSTS');
    add_settings_field( 'field_HSTS_subdomain', 'HSTS to include subdomains', 'field_HSTS_subdomain_callback', 'security_headers', 'section_HSTS');
    add_settings_field( 'field_HSTS_preload', 'HSTS include site in preload list', 'field_HSTS_preload_callback', 'security_headers', 'section_HSTS');
    add_settings_section('section_HPKP', 'HTTP Public Key Pinning', 'section_HPKP_callback', 'security_headers');
    add_settings_field( 'field_HPKP_time', 'HPKP Time to live (seconds)', 'field_HPKP_time_callback', 'security_headers', 'section_HPKP');
    add_settings_field( 'field_HPKP_subdomain', 'HPKP to include subdomains', 'field_HPKP_subdomain_callback', 'security_headers', 'section_HPKP');
    add_settings_field( 'field_HPKP_key1', 'HPKP first key', 'field_HPKP_key1_callback', 'security_headers', 'section_HPKP');
    add_settings_field( 'field_HPKP_key2', 'HPKP backup key', 'field_HPKP_key2_callback', 'security_headers', 'section_HPKP');
    add_settings_field( 'field_HPKP_key3', 'HPKP optional backup key', 'field_HPKP_key3_callback', 'security_headers', 'section_HPKP');
    add_settings_field( 'field_HPKP_uri', 'HPKP Reporting URI', 'field_HPKP_uri_callback', 'security_headers', 'section_HPKP');
}
add_action('admin_init', 'security_headers_activate');
add_action('admin_menu', 'security_headers_settings');

function section_HEAD_callback() {
    echo '<p>Security headers unrelated to HSTS or HPKP.</p>';
    echo '<p>Always disable <a href="https://blogs.msdn.microsoft.com/ie/2008/09/02/ie8-security-part-vi-beta-2-update/">Content sniffing</a>.</p>';
    echo '<p>XSS protection is enabled by default in IE and Chrome, but they try to clean up XSS requests; this setting ensures this behaviour is on in the browser even if the user disabled it, and that requests that trigger the warning are blocked and shown to the user, rather than silently mangled.</p>';
    echo '<p>Restrict framing prevent clickjacking in the main site, WordPress already sets this restriction for the admin and login pages.</p>';
}

function section_HSTS_callback() {
    echo '<p>Only enable HSTS when you have a working site over HTTPS with no errors, with redirects from http to https.</p>';
    echo '<p>We recommend you enable it with a small time to live (say 300s) initially, and increase after testing the site.</p>';
    echo '<p>A blank field means no header, "0" means remove HSTS, and an integer is a time in seconds</p>';
    echo '<p>Include subdomains means all subdomains will use HTTPS.<br> Beware if serving "example.com" from server usually known as "www.example.com" this would mean any subdomain of "example.com" to someone visiting via that name if the certificate covers it. </p>';
    echo '<p>Include site in preload list means browser authors may add it to their hardcoded list, tick when you are sure HSTS is right for youir site.</p>';
}

function field_HSTS_time_callback() {
    $setting = esc_attr(get_option('security_headers_hsts_time'));
    echo "<input type='text' name='security_headers_hsts_time' value='$setting' />";
}

function field_HSTS_subdomain_callback() {
    $setting = esc_attr(get_option('security_headers_hsts_subdomains'));
    echo "<input type='checkbox' name='security_headers_hsts_subdomains' value='1' ";
    checked($setting, "1");
    echo " />";
}

function field_HSTS_preload_callback() {
    $setting = esc_attr(get_option('security_headers_hsts_preload'));
    echo "<input type='checkbox' name='security_headers_hsts_preload' value='1' ";
    checked($setting, "1");
    echo " />";
}

function field_HSTS_nosniff_callback() {
    $setting = esc_attr(get_option('security_headers_nosniff'));
    echo "<input type='checkbox' name='security_headers_nosniff' value='1' ";
    checked($setting, "1");
    echo " />";
}

function field_HSTS_xss_callback() {
    $setting = esc_attr(get_option('security_headers_xss'));
    echo "<input type='checkbox' name='security_headers_xss' value='1' ";
    checked($setting, "1");
    echo " />";
}

function field_HSTS_frame_callback() {
    $setting = esc_attr(get_option('security_headers_frame'));
    echo "<input type='checkbox' name='security_headers_frame' value='1' ";
    checked($setting, "1");
    echo " />";
}

function section_HPKP_callback() {
    echo '<p>Include the subdomains to ensure they can\'t be used to extract cookies or other sensitive data.</p>';
    echo 'Keys are base64 encoded SHA256 of the public key see <a href="https://waters.me/wordpress/hpkp-pinning-policy/">HPKP Pinning policy</a> for details and a command reference.</p>';
}


function field_HPKP_time_callback() {
    $setting = esc_attr(get_option('security_headers_hpkp_time'));
    echo "<input type='text' name='security_headers_hpkp_time' value='$setting' />";
}

function field_HPKP_subdomain_callback() {
    $setting = esc_attr(get_option('security_headers_hpkp_subdomains'));
    echo "<input type='checkbox' name='security_headers_hpkp_subdomains' value='1' ";
    checked($setting, "1");
    echo " />";
}

function field_HPKP_key1_callback() {
    $setting = esc_attr(get_option('security_headers_hpkp_key1'));
    echo "<input type='text' name='security_headers_hpkp_key1' value='$setting' />";
}

function field_HPKP_key2_callback() {
    $setting = esc_attr(get_option('security_headers_hpkp_key2'));
    echo "<input type='text' name='security_headers_hpkp_key2' value='$setting' />";
}

function field_HPKP_key3_callback() {
    $setting = esc_attr(get_option('security_headers_hpkp_key3'));
    echo "<input type='text' name='security_headers_hpkp_key3' value='$setting' />";
}

function field_HPKP_uri_callback() {
    $setting = esc_attr(get_option('security_headers_hpkp_uri'));
    echo "<input type='text' name='security_headers_hpkp_uri' value='$setting' />";
}

function ischecked($input) {
    $result = "0";
    if ("1" === $input) {
        $result = "1" ;
    }

    return $result;
}

function istime($input) {
    // Two results either empty string - no header - or natural number (header) as "0" means remove HSTS/HPKP from this domain
    $result = "";
    if (ctype_digit($input)) {
        $result = $input ;
    }

    return $result;
}

function iskey($input) {
    $result="";
    if (preg_match("/^[a-zA-Z0-9+\/]{43}=$/", $input)){ // base 64 of 256 bit with equal sign added
     $result=$input;
    }
    return $result ;
}

function isuri($input) {
    $result="";
    if (preg_match('%^(?:(?:https?|ftp)://)(?:\S+(?::\S*)?@|\d{1,3}(?:\.\d{1,3}){3}|(?:(?:[a-z\d\x{00a1}-\x{ffff}]+-?)*[a-z\d\x{00a1}-\x{ffff}]+)(?:\.(?:[a-z\d\x{00a1}-\x{ffff}]+-?)*[a-z\d\x{00a1}-\x{ffff}]+)*(?:\.[a-z\x{00a1}-\x{ffff}]{2,6}))(?::\d+)?(?:[^\s]*)?$%iu', $input)){ // https://mathiasbynens.be/demo/url-regex diegoperini 
     $result=$input;
    }
    return $result ;
}
