security_headers
================

Wordpress plug-in to set HSTS, HPKP and other security headers in a Wordpress site.

HPKP Pinning is documented: https://waters.me/wordpress/hpkp-pinning-policy/

The plugin will only accept well formed keys, and will only emit headers over TLS (as mandated by the specification).

At least one backup key must be specified for the Public-Key-Pins header to be emitted.

HSTS is described here: https://www.owasp.org/index.php/HTTP_Strict_Transport_Security

The plugin will only emit the Strict-Transport-Security header over TLS.

See readme.txt for the regular Wordpress meta-data and technical description.
