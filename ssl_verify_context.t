#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for http ssl module, ssl_verify_client and verification context checks.

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/http http_ssl sni rewrite socket_ssl_sni/)
	->has_daemon('openssl')
	->plan(15)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    add_header X-SSL-Protocol $ssl_protocol always;
    add_header X-SSL-Verify $ssl_client_verify always;
    add_header X-SSL-Client $ssl_client_s_dn always;
    add_header X-SSL-Reused $ssl_session_reused always;
    add_header X-SSL-Name $ssl_server_name always;

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  localhost;

        ssl_certificate localhost.crt;
        ssl_certificate_key localhost.key;

        ssl_verify_client optional;
        ssl_client_certificate localhost.crt;

        location / {
            return 200 $server_name:$ssl_server_name:$ssl_session_reused;
        }
    }

    server {
        listen       127.0.0.1:8443;
        server_name  nocontext;

        ssl_verify_client on;

        location / {
            return 200 $server_name:$ssl_server_name:$ssl_session_reused;
        }
    }

    server {
        listen       127.0.0.1:8443;
        server_name  one;

        ssl_certificate one.crt;
        ssl_certificate_key one.key;

        ssl_verify_client on;
        ssl_client_certificate one.crt;

        location / {
            return 200 $server_name:$ssl_server_name:$ssl_session_reused;
        }
    }

    server {
        listen       127.0.0.1:8443;
        server_name  two;

        ssl_certificate two.crt;
        ssl_certificate_key two.key;

        ssl_verify_client on;
        ssl_client_certificate two.crt;

        location / {
            return 200 $server_name:$ssl_server_name:$ssl_session_reused;
        }
    }

    server {
        listen       127.0.0.1:8443;
        server_name  twobis;

        ssl_certificate two.crt;
        ssl_certificate_key two.key;

        ssl_verify_client on;
        ssl_client_certificate two.crt;
        ssl_trusted_certificate one.crt;

        location / {
            return 200 $server_name:$ssl_server_name:$ssl_session_reused;
        }
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

foreach my $name ('localhost', 'one', 'two') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->run();

###############################################################################

# Tests for various HTTP-level requests of servers which do not match
# negotiated server name.

# Following 5095:4fbef397c753, these are somewhat restricted to ensure
# that client certificates verified in a virtual server cannot be used
# in other virtual servers with client certificate verification configured,
# as these can use different CA certificates configured.  Still, requests
# from non-SNI clients are allowed in all virtual servers.

# for non-SNI clients, requests to all servers are allowed

my $ctx = new IO::Socket::SSL::SSL_Context(
	SSL_version => 'SSLv23',
	SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
	SSL_cert_file => "$d/localhost.crt",
	SSL_key_file => "$d/localhost.key"
	);

like(get('', '', $ctx), qr/^localhost::/m,
	'http, no server name, default server');
like(get('', 'one', $ctx), qr/^one::/m,
	'http, no server name, virtual server');
like(get('', 'nocontext', $ctx), qr/^nocontext::/m,
	'http, no server name, no context');


# with SNI, corresponding virtual server is allowed,
# but other virtual servers return 421 (Misdirected Request) error
# (if there is client certificate verification configured)

my $ctx1 = new IO::Socket::SSL::SSL_Context(
	SSL_version => 'SSLv23',
	SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
	SSL_cert_file => "$d/one.crt",
	SSL_key_file => "$d/one.key"
	);

like(get('one', 'one', $ctx1), qr/^one:one:/m,
	'http, server name');
like(get('one', 'two', $ctx1), qr/421 Misdirected/,
	'http, server name, other server rejected');
like(get('one', '', $ctx1), qr/421 Misdirected/,
	'http, server name, default server rejected');
like(get('localhost', 'one', $ctx1), qr/421 Misdirected/,
	'http, server name, default to virtual rejected');

like(get('nocontext', 'nocontext', $ctx), qr/^nocontext:nocontext:/m,
	'http, server name, no context');
like(get('one', 'nocontext', $ctx1), qr/421 Misdirected/,
	'http, server name, virtual to no context rejected');

# Tests for session reuse with different names.

# OpenSSL 1.1.1e+ with TLSv1.3 allows session resumption
# with names other than initially negotiated

# BoringSSL allows session resumption with names other than
# initially negotiated, but checks session id context of the
# SNI-selected server

# LibreSSL does not support session resumption with TLSv1.3,
# and with older protocols rejects hanshakes trying to resume
# a session with a different name

$ctx = new IO::Socket::SSL::SSL_Context(
	SSL_version => 'SSLv23',
	SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
	SSL_session_cache_size => 100,
	SSL_cert_file => "$d/one.crt",
	SSL_key_file => "$d/one.key"
	);

like(get('one', 'one', $ctx), qr/^one:one:\.$/m,
	'ssl server name');

TODO: {
local $TODO = 'no TLSv1.3 sessions, old Net::SSLeay'
	if $Net::SSLeay::VERSION < 1.88 && test_tls13();
local $TODO = 'no TLSv1.3 sessions, old IO::Socket::SSL'
	if $IO::Socket::SSL::VERSION < 2.061 && test_tls13();
local $TODO = 'no TLSv1.3 sessions in LibreSSL'
	if $t->has_module('LibreSSL') && test_tls13();
local $TODO = 'no TLSv1.3 sessions in Net::SSLeay (LibreSSL)'
	if Net::SSLeay::constant("LIBRESSL_VERSION_NUMBER") && test_tls13();

like(get('one', 'one', $ctx), qr/^one:one:r$/m,
	'ssl server name, reused');

}

TODO: {
local $TODO = 'not yet'
	if !$t->has_version('1.27.5')
	&& ($t->has_feature('openssl:1.1.1e') && test_tls13());

like(get('two', 'two', $ctx), qr/(421 Misdirected|400 Bad|^$)/,
	'ssl server name, reuse in other server rejected');

like(get('', '', $ctx), qr/(421 Misdirected|400 Bad|^$)/,
	'ssl server name, reuse in default server rejected');

}

# for mostly identical servers (same certificate, same client CA list)
# make sure different trusted certificates is enough to prevent reuse

$ctx = new IO::Socket::SSL::SSL_Context(
	SSL_version => 'SSLv23',
	SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
	SSL_session_cache_size => 100,
	SSL_cert_file => "$d/one.crt",
	SSL_key_file => "$d/one.key"
	);

like(get('twobis', 'twobis', $ctx), qr/^twobis:twobis:\.$/m,
	'ssl server name, trusted');

TODO: {
local $TODO = 'not yet'
	if !$t->has_version('1.27.5')
	&& (($t->has_feature('openssl:1.1.1e') && test_tls13())
	|| $t->has_module('BoringSSL'));

like(get('two', 'two', $ctx), qr/(421 Misdirected|400 Bad|^$)/,
	'ssl server name, different trusted rejected');

}

###############################################################################

sub test_tls13 {
	get() =~ /TLSv1.3/;
}

sub get {
	my ($sni, $host, $ctx) = @_;
	return http(
		"GET / HTTP/1.0" . CRLF .
		($host ? "Host: $host" . CRLF : "") . CRLF,
		SSL => 1,
		SSL_hostname => $sni,
		SSL_reuse_ctx => $ctx
	);
}

###############################################################################
