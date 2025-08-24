#!/usr/bin/perl

# (C) Maxim Dounin

# Test for http backend returning response with duplicate "Transfer-Encoding:
# chunked" headers and the "proxy_allow_duplicate_chunked" directive.

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

my $t = Test::Nginx->new()->has(qw/http proxy/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
        }

        location /allow/ {
            proxy_pass http://127.0.0.1:8081;
            proxy_read_timeout 1s;
            proxy_allow_duplicate_chunked on;
        }
    }
}

EOF

$t->run_daemon(\&http_daemon);
$t->try_run('no proxy_allow_duplicate_chunked')->plan(3);
$t->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

like(http_get('/'), qr/200 OK/, 'normal');

like(http_get('/duplicate-chunked'), qr/502 Bad/,
	'duplicate transfer encoding');

like(http_get('/allow/duplicate-chunked'), qr/200 OK/,
	'duplicate transfer encoding allowed');

###############################################################################

sub http_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => '127.0.0.1:' . port(8081),
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		my $headers = '';
		my $uri = '';

		while (<$client>) {
			$headers .= $_;
			last if (/^\x0d?\x0a?$/);
		}

		$uri = $1 if $headers =~ /^\S+\s+([^ ]+)\s+HTTP/i;

		if ($uri eq '/') {

			print $client
				'HTTP/1.1 200 OK' . CRLF .
				'Connection: close' . CRLF .
				'Content-Length: 0' . CRLF . CRLF;

		} elsif ($uri =~ m/duplicate-chunked/) {

			print $client
				'HTTP/1.1 200 OK' . CRLF .
				'Connection: close' . CRLF .
				'Transfer-Encoding: chunked' . CRLF .
				'Transfer-Encoding: chunked' . CRLF . CRLF .
				'0' . CRLF . CRLF;

		}

		close $client;
	}
}

###############################################################################
