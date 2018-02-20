=== Security Headers ===
Contributors: Simon Waters
Tags: TLS,HTTPS,HSTS,nosniff
Requires at least: 3.8.1
Tested up to: 4.9
Requires PHP: 5.6
Stable tag: trunk
License: GPLv2 or any later version
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Plug-in to ease the setting of TLS headers for HSTS and similar

== Description ==

TLS is growing in complexity. Server Name Indication (SNI) now means HTTPS sites may be on shared IP addresses, or otherwise restricted. For these servers it is handy to be able to set desired HTTP headers without access to the web servers configuration or using .htaccess file.

This plug-in exposes controls for:

* HSTS (Strict-Transport-Security)
* HPKP (Public-Key-Pins)
* Disabling content sniffing (X-Content-Type-Options)
* XSS protection (X-XSS-Protection)
* Clickjacking mitigation (X-Frame-Options in main site)
* Expect-CT

HSTS is used to ensure that future connections to a website always use TLS, and disallowing bypass of certificate warnings for the site.

HPKP is used if you don't want to rely solely on the Certificate Authority trust model for certificate issuance.

Disabling content sniffing is mostly of interest for sites that allow users to upload files of specific types, but that browsers might be silly enough to interpret of some other type, thus allowing unexpected attacks.  

XSS protection re-enables XSS protection for the site, if the user has disabled it previously, and sets the "block" option so that attacks are not silently ignored.

Clickjacking protection is usually only relevant when someone is logged in but users requested it, presumably they have rich content outside of WordPress authentication they wish to protect.

Expect-CT is used to ensure Certificate Transparency is configured correctly.

== Installation ==
1. Upload "security_headers.php" to the "/wp-content/plugins/" directory.
2. Activate the plugin through the "Plugins" menu in WordPress.

== Changelog ==

= 1.0 =

Add support for wp-login.php page

Add support for Expect-CT header

= 0.9 =

Removed unnecessary whitespace in HSTS header (thanks Thomas)

Added Referrer-Policy header

Corrected plugins name from "HTTP Headers" to "Security Header" (thanks Jamie)

Removed trailing semi-colon from X-XSS-Protection (it worked but not needed)

= 0.8 =

Add headers to admin section of WordPress

Added option to set the X-Frame-Options headers to main site

Added HSTS Preload header (thanks to Jamie)

= 0.7 =

Add report-uri 

Fix handling of non-numeric blank strings for HPKP max-age

= 0.6 =

HPKP support

Check for TLS before emitting HSTS or HPKP headers

= 0.5 =

Change h2 for h1 for accessibility per #31650

= 0.4 =

License change
Clarify wording for XSS protection in readme

= 0.3 =

Prepare for release

= 0.2 =

Added Sonarqube file and formatting changes

= 0.1 =
* Initial release.

== Upgrade Notice ==

= 1.0 =
* Added support for wp-login.php

