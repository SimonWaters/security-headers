=== Security Headers ===
Contributors: Simon Waters
Tags: TLS,HTTPS,HSTS,nosniff
Requires at least: 3.8.1
Tested up to: 3.8.1
Stable tag: trunk
License: GPLv2
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Plug-in to ease the setting of TLS headers for HSTS and similar

== Description ==

TLS is growing in complexity. Server Name Indication now means HTTPS sites
may be on shared IP addresses, or otherwise restricted. For these
servers it is handy to be able to set desired headers without access to
the web servers configuration or using .htaccess file.

Wordpress has set the X-Frame-Option header since version 3.2.

This plug-in exposes controls for:


* HSTS (Strict-Transport-Security)
* Disabling content sniffing (X-Content-Type-Options)
* XSS protection (X-XSS-Protection)

HSTS is used to ensure that futue connections to a website always use TLS,
and disallowing bypass of certificate warnings for the site.

Disabling content sniffing is mostly of interest for sites that allow users to upload files of specific types, but that browsers might be silly enough to interpret of some other type, thus allowing unexpected attacks.

XSS protection re-enabled XSS protection if the user has disabled it for the site.

== Installation ==
1. Upload \"security_headers.php\" to the \"/wp-content/plugins/\" directory.
1. Activate the plugin through the \"Plugins\" menu in WordPress.

== Changelog ==

= 0.3 =

Prepare for release

= 0.2 =

Added Sonarqube file and formatting changes

= 0.1 =
* Initial release.

== Upgrade Notice ==

= 0.2 =
* Code quality work

