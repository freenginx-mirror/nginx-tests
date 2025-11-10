#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for http ssl module, loading "store:..." certificate and keys.
# Uses internal "file:" scheme for testing, as available in OpenSSL 1.1.1
# and later.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/http proxy http_ssl openssl:1.1.1 sni socket_ssl_sni/)
	->has_daemon('openssl');

plan(skip_all => 'no store:... keys')
	unless $t->has_version('1.29.3');
plan(skip_all => 'no store:... keys in BoringSSL')
	if $t->has_module('BoringSSL');

$t->write_file_expand('nginx.conf', <<'EOF')->plan(10);

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  localhost;

        ssl_certificate store:file:///%%TESTDIR%%/localhost.crt;
        ssl_certificate_key store:file:///%%TESTDIR%%/localhost.key;
    }

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  crt_key;

        ssl_certificate store:file:///%%TESTDIR%%/localhost.crt_key;
        ssl_certificate_key store:file:///%%TESTDIR%%/localhost.crt_key;
    }

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  key_crt;

        ssl_certificate store:file:///%%TESTDIR%%/localhost.key_crt;
        ssl_certificate_key store:file:///%%TESTDIR%%/localhost.key_crt;
    }

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  encrypted;

        ssl_password_file passwords;
        ssl_certificate store:file:///%%TESTDIR%%/encrypted.crt;
        ssl_certificate_key store:file:///%%TESTDIR%%/encrypted.key;
    }

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  encrypted_crt_key;

        ssl_password_file passwords;
        ssl_certificate store:file:///%%TESTDIR%%/encrypted.crt_key;
        ssl_certificate_key store:file:///%%TESTDIR%%/encrypted.crt_key;
    }

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  encrypted_key_crt;

        ssl_password_file passwords;
        ssl_certificate store:file:///%%TESTDIR%%/encrypted.key_crt;
        ssl_certificate_key store:file:///%%TESTDIR%%/encrypted.key_crt;
    }

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  dynamic no_password;

        ssl_certificate store:file:///%%TESTDIR%%/$ssl_server_name.crt;
        ssl_certificate_key store:file:///%%TESTDIR%%/$ssl_server_name.key;
    }

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  password;

        ssl_password_file password;
        ssl_certificate store:file:///%%TESTDIR%%/$ssl_server_name.crt;
        ssl_certificate_key store:file:///%%TESTDIR%%/$ssl_server_name.key;
    }

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  multiple;

        ssl_password_file passwords;
        ssl_certificate store:file:///%%TESTDIR%%/$ssl_server_name.crt;
        ssl_certificate_key store:file:///%%TESTDIR%%/$ssl_server_name.key;
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

foreach my $name ('localhost', 'dynamic') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. "-nodes "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

foreach my $name ('encrypted', 'password', 'multiple') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. "-passout pass:secret "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->write_file('localhost.crt_key',
	$t->read_file('localhost.crt') . $t->read_file('localhost.key'));
$t->write_file('localhost.key_crt',
	$t->read_file('localhost.key') . $t->read_file('localhost.crt'));

$t->write_file('encrypted.crt_key',
	$t->read_file('encrypted.crt') . $t->read_file('encrypted.key'));
$t->write_file('encrypted.key_crt',
	$t->read_file('encrypted.key') . $t->read_file('encrypted.crt'));

$t->write_file('index.html', '');
$t->write_file('password', "secret\n");
$t->write_file('passwords', "foo\nbar\nsecret\n");

$t->run();

###############################################################################

like(http_get('/', SSL => 1), qr/200 OK/, 'ssl store');

like(http_get('/', SSL => 1, SSL_hostname => 'crt_key'), qr/200 OK/,
	'ssl store crt and key');

like(http_get('/', SSL => 1, SSL_hostname => 'key_crt'), qr/200 OK/,
	'ssl store key and crt');

like(http_get('/', SSL => 1, SSL_hostname => 'encrypted'), qr/200 OK/,
	'ssl store encrypted');

like(http_get('/', SSL => 1, SSL_hostname => 'encrypted_crt_key'), qr/200 OK/,
	'ssl store encrypted crt and key');

like(http_get('/', SSL => 1, SSL_hostname => 'encrypted_key_crt'), qr/200 OK/,
	'ssl store encrypted key and crt');

like(http_get('/', SSL => 1, SSL_hostname => 'dynamic'), qr/200 OK/,
	'ssl store variable');

is(http_get('/', SSL => 1, SSL_hostname => 'no_password'), undef,
	'ssl store encrypted no password');

like(http_get('/', SSL => 1, SSL_hostname => 'password'), qr/200 OK/,
	'ssl store encrypted one password');

like(http_get('/', SSL => 1, SSL_hostname => 'multiple'), qr/200 OK/,
	'ssl store encrypted multiple passwords');

###############################################################################
