#!/usr/bin/perl

# (C) Maxim Dounin
# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for http ssl module, loading "engine:..." keys.

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

plan(skip_all => 'may not work')
	unless $ENV{TEST_NGINX_UNSAFE};

my $t = Test::Nginx->new()
	->has(qw/http proxy http_ssl/)
	->has_daemon('openssl')
	->has_daemon('softhsm2-util')
	->has_daemon('pkcs11-tool');

plan(skip_all => 'no engine:... keys')
	unless $t->has_module('OpenSSL') and !$t->has_module('BoringSSL');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8081 ssl;
        listen       127.0.0.1:8080;
        server_name  localhost;

        ssl_certificate localhost.crt;
        ssl_certificate_key engine:pkcs11:id_00;

        location / {
            # index index.html by default
        }

        location /proxy {
            proxy_pass https://127.0.0.1:8081/;
        }

        location /var {
            proxy_pass https://127.0.0.1:8082/;
            proxy_ssl_name localhost;
            proxy_ssl_server_name on;
        }
    }

    server {
        listen       127.0.0.1:8082 ssl;
        server_name  localhost;

        ssl_certificate $ssl_server_name.crt;
        ssl_certificate_key engine:pkcs11:id_00;

        location / {
            # index index.html by default
        }
    }
}

EOF

# Create a SoftHSM token with a secret key, and configure OpenSSL
# to access it using the pkcs11 engine, see detailed example
# posted by Dmitrii Pichulin here:
#
# http://mailman.nginx.org/pipermail/nginx-devel/2014-October/006151.html
#
# Note that library paths are different on different systems.  We try
# to detect some known ones.
#
# Still, detected libraries might not match OpenSSL library used when
# building nginx, or the "openssl" tool in path, so everything will fail.
# As such, this test is marked unsafe.

# Libraries on various systems: FreeBSD, Alpine, Ubuntu

my ($engine) = grep { -e $_ } qw!
	/usr/local/lib/engines/pkcs11.so
	/usr/lib/engines-3/pkcs11.so
	/usr/lib/x86_64-linux-gnu/engines-3/pkcs11.so
!;

my ($softhsm) = grep { -e $_ } qw!
	/usr/local/lib/softhsm/libsofthsm2.so
	/usr/lib/softhsm/libsofthsm2.so
	/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
!;

plan(skip_all => 'no libp11 pkcs11 engine') unless $engine;
plan(skip_all => 'no softhsm2') unless $softhsm;

$t->write_file('openssl.conf', <<EOF);
openssl_conf = openssl_def

[openssl_def]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = $engine
MODULE_PATH = $softhsm
init = 1
PIN = 1234

[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

$t->write_file('softhsm2.conf', <<EOF);
directories.tokendir = $d/tokens/
objectstore.backend = file
EOF

mkdir($d . '/tokens');

$ENV{SOFTHSM2_CONF} = "$d/softhsm2.conf";
$ENV{OPENSSL_CONF} = "$d/openssl.conf";

foreach my $name ('localhost') {
	system('softhsm2-util --init-token --slot 0 --label token0 '
		. '--pin 1234 --so-pin 1234 '
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't initialize softhsm token: $!\n";

	system('pkcs11-tool '
		. "--module=$softhsm "
		. '--token-label token0 --pin 1234 --login '
		. '--keypairgen --id 0 --label key0 --key-type rsa:2048 '
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't generate pkcs11 keypair: $!\n";

	system('openssl req -x509 -new '
		. "-subj /CN=$name/ -out $d/$name.crt -text "
		. "-engine pkcs11 -keyform engine -key id_00 "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->run()->plan(2);

$t->write_file('index.html', '');

###############################################################################

like(http_get('/proxy'), qr/200 OK/, 'ssl engine keys');
like(http_get('/var'), qr/200 OK/, 'ssl_certificate with variable');

###############################################################################
