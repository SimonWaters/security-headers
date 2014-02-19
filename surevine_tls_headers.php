<?php
/**
 * Plugin Name: HTTP Headers
 * Plugin URI: http://surevine.com/
 * Description: Sets security related headers (HSTS etc)
 * Version: 0.1
 * Author: Simon Waters (Surevine Ltd)
 * Author URI: http://waters.me/
 * License: GPL2
 */

function surevine_tls_headers_insert()
{
if ( headers_sent() ) {
 error_log("Headers already sent HTTP Headers modules unable to function");
}

 # HSTS
 $time = esc_attr( get_option( 'surevine_tls_headers_hsts_time' ) );
 $subdomain = esc_attr( get_option( 'surevine_tls_headers_hsts_subdomains' ) );
 if ( ctype_digit($time)  ) {
    if ($subdomain > 0) {
         header("Strict-Transport-Security: max-age=$time ; includeSubDomains");
    } else {
         header("Strict-Transport-Security: max-age=$time");
    }
 }

 # No Sniff
 $nosniff = esc_attr( get_option( 'surevine_tls_headers_nosniff' ) );
 if ($nosniff == 1) {  send_nosniff_header(); }

 # XSS
 $xss = esc_attr( get_option( 'surevine_tls_headers_xss' ) );
 if ($xss == 1) {  header("X-XSS-Protection: 1; mode=block;"); }

}
add_action( 'send_headers', 'surevine_tls_headers_insert');

function surevine_tls_headers_activate()
{
 register_setting('surevine_tls_group', 'surevine_tls_headers_hsts_time', 'istime' );
 register_setting('surevine_tls_group', 'surevine_tls_headers_hsts_subdomains', 'ischecked' );
 register_setting('surevine_tls_group', 'surevine_tls_headers_nosniff', 'ischecked' );
 register_setting('surevine_tls_group', 'surevine_tls_headers_xss', 'ischecked' );

}

register_activation_hook( __FILE__, 'surevine_tls_headers_activate' );

function surevine_tls_headers_deactivate()
{
 remove_action( 'admin_menu', 'surevine_tls_headers_settings' );
 remove_action( 'send_headers', 'surevine_tls_headers');

 unregister_setting('surevine_tls_group', 'surevine_tls_headers_hsts_time', 'istime' );
 unregister_setting('surevine_tls_group', 'surevine_tls_headers_hsts_subdomains', 'ischecked' );
 unregister_setting('surevine_tls_group', 'surevine_tls_headers_nosniff', 'ischecked' );
 unregister_setting('surevine_tls_group', 'surevine_tls_headers_xss', 'ischecked' );

}
register_deactivation_hook( __FILE__, 'surevine_tls_headers_deactivate' );

function surevine_tls_headers_display_form()
{
 echo '<div class="wrap">';
  echo '<h2>Options for HTTP Headers</h2>';
  echo '<form action="options.php" method="POST">';
   settings_fields('surevine_tls_group');
   do_settings_sections('surevine_tls_headers');
   submit_button();
  echo '</form>';
 echo '</div>';
}

function surevine_tls_headers_settings()
{
 add_options_page('HTTP Headers','HTTP Headers','manage_options','surevine_tls_headers','surevine_tls_headers_display_form');
 add_settings_section('section_HSTS', 'HTTP Security Related Headers', 'section_HSTS_callback', 'surevine_tls_headers' );
 add_settings_field( 'field_HSTS_time', 'HSTS Time to live (seconds)', 'field_HSTS_time_callback', 'surevine_tls_headers', 'section_HSTS' );
 add_settings_field( 'field_HSTS_subdomain', 'HSTS to include subdomains', 'field_HSTS_subdomain_callback', 'surevine_tls_headers', 'section_HSTS' );
 add_settings_field( 'field_HSTS_nosniff', 'Disable content sniffing', 'field_HSTS_nosniff_callback', 'surevine_tls_headers', 'section_HSTS' );
 add_settings_field( 'field_HSTS_xss', 'Enable Chrome XSS protection', 'field_HSTS_xss_callback', 'surevine_tls_headers', 'section_HSTS' );
}
add_action( 'admin_init', 'surevine_tls_headers_activate' );
add_action( 'admin_menu', 'surevine_tls_headers_settings' );

function section_HSTS_callback()
{
 echo '<p>Only enable HSTS when you have a working site over HTTPS with no errors, with redirects from http to https.</p>';
 echo '<p>We recommend you enable it with a small time to live (say 300s) initially, and increase after testing the site.</p>';
 echo '<p>A blank field means no header, "0" means remove HSTS, and an integer is a time in seconds</p>';
 echo '<p>Include subdomains means all subdomains will use HTTPS.<br> Beware if serving "example.com" from server usually known as "www.example.com" this would mean any subdomain of "example.com" to someone visiting via that name if the certificate covers it. </p>';
}

function field_HSTS_time_callback()
{
    $setting = esc_attr( get_option( 'surevine_tls_headers_hsts_time' ) );
    echo "<input type='text' name='surevine_tls_headers_hsts_time' value='$setting' />";
}

function field_HSTS_subdomain_callback()
{
    $setting = esc_attr( get_option( 'surevine_tls_headers_hsts_subdomains' ) );
    echo "<input type='checkbox' name='surevine_tls_headers_hsts_subdomains' value='1' ";
    checked($setting,"1");
    echo " />";
}

function field_HSTS_nosniff_callback()
{
    $setting = esc_attr( get_option( 'surevine_tls_headers_nosniff' ) );
    echo "<input type='checkbox' name='surevine_tls_headers_nosniff' value='1' ";
    checked($setting,"1");
    echo " />";
}

function field_HSTS_xss_callback()
{
    $setting = esc_attr( get_option( 'surevine_tls_headers_xss' ) );
    echo "<input type='checkbox' name='surevine_tls_headers_xss' value='1' ";
    checked($setting,"1");
    echo " />";
}

function ischecked($input)
{
 $result = "0";
 if ("1" === $input) { $result = "1" ; }

 return $result;
}

function istime($input)
{
    # Two results either empty string - no header - or natural number (header) as "0" means remove HSTS from this domain
    $result = "";
    if ( ctype_digit($input) ) { $result = $input ; }

    return $result;
}

/* Validation needs to ensure WP_SITEURL starts "https" */
