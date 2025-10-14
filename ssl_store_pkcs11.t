#!/usr/bin/perl

# (C) Maxim Dounin
# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for http ssl module, loading "store:..." certificates and keys
# from pkcs11-provider (https://github.com/latchset/pkcs11-provider).

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

plan(skip_all => 'no store:... keys')
	unless $t->has_module('OpenSSL') and !$t->has_module('BoringSSL');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

# pkcs11-provider tries to reinitialize softhsm after fork(),
# so we need softhsm2 environment variable in worker processes

env SOFTHSM2_CONF;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8081 ssl;
        listen       127.0.0.1:8080;
        server_name  localhost;

        ssl_certificate store:pkcs11:object=cert-localhost;
        ssl_certificate_key store:pkcs11:object=key0;

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

        ssl_certificate store:pkcs11:object=cert-$ssl_server_name;
        ssl_certificate_key store:pkcs11:object=key0;

        location / {
            # index index.html by default
        }
    }
}

EOF

# Create a SoftHSM token with a secret key, and configure OpenSSL
# to access it using pkcs11-provider.  See detailed example posted
# by Dmitrii Pichulin here:
#
# http://mailman.nginx.org/pipermail/nginx-devel/2014-October/006151.html
#
# Adapted to provider usage based on libp11 documentation and
# pkcs11-provider documentation, see here:
#
# https://github.com/OpenSC/libp11
# https://github.com/latchset/pkcs11-provider
#
# Note that library paths are different on different systems.  We try
# to detect some known ones.
#
# Still, detected libraries might not match OpenSSL library used when
# building nginx, or the "openssl" tool in path, so everything will fail.
# As such, this test is marked unsafe.
#
# Note well that pkcs11-provider asks for PIN after fork() via the default
# user interface (not the one explicitly passed to OSSL_STORE_open())
# if PIN is not explicitly provided in the provider configuration with
# "pkcs11-module-token-pin = ..." and/or PIN caching is not explicitly
# enabled with "pkcs11-module-cache-pins = cache".  Even "pin-value=..." in
# PKCS#11 URI is not enough.  We use PIN in the configuration explicitly
# set with "pkcs11-module-token-pin = 1234".
#
# Additionally, old versions of pkcs11-provider need various quirks
# to work with SoftHSM.  In particular, pkcs11-provider 0.3 as seen
# on Ubuntu 24.04 needs at least:
#
# pkcs11-module-load-behavior = early
# pkcs11-module-quirks = no-operation-state
#
# No quirks are needed with pkcs11-provider 1.0+.

# Libraries on various systems: FreeBSD, Alpine, Debian, Fedora

my ($provider) = grep { -e $_ } qw!
	/usr/local/lib/ossl-modules/pkcs11.so
	/usr/lib/ossl-modules/pkcs11.so
	/usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so
	/usr/lib64/ossl-modules/pkcs11.so
!;

my ($softhsm) = grep { -e $_ } qw!
	/usr/local/lib/softhsm/libsofthsm2.so
	/usr/lib/softhsm/libsofthsm2.so
	/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
	/usr/lib64/pkcs11/libsofthsm2.so
!;

plan(skip_all => 'no pkcs11-provider') unless $provider;
plan(skip_all => 'no softhsm2') unless $softhsm;

$t->write_file('openssl.conf', <<EOF);
openssl_conf = openssl_def

[openssl_def]
providers = provider_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
module = $provider
pkcs11-module-path = $softhsm
pkcs11-module-token-pin = 1234
pkcs11-module-load-behavior = early
pkcs11-module-quirks = no-operation-state
activate = 1

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
		. "-key pkcs11:object=key0 "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";

	system('pkcs11-tool '
		. "--module=$softhsm "
		. '--token-label token0 --pin 1234 --login '
		. "--write-object $d/$name.crt --type cert --label cert-$name "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't store certificate to pkcs11 token: $!\n";
}

$t->run()->plan(2);

$t->write_file('index.html', '');

###############################################################################

like(http_get('/proxy'), qr/200 OK/, 'ssl store pkcs11-provider');
like(http_get('/var'), qr/200 OK/, 'ssl_certificate with variable');

###############################################################################
