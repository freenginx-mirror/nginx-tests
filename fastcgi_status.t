#!/usr/bin/perl

# (C) Maxim Dounin

# Test for fastcgi backend returning various status codes.

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

eval { require FCGI; };
plan(skip_all => 'FCGI not installed') if $@;
plan(skip_all => 'win32') if $^O eq 'MSWin32';

my $t = Test::Nginx->new()
	->has(qw/http fastcgi/)->plan(11)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    fastcgi_param REQUEST_URI $request_uri;
    fastcgi_param REQUEST_METHOD $request_method;

    fastcgi_read_timeout 10s;
    add_header X-Upstream-Status $upstream_status;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            fastcgi_pass 127.0.0.1:8081;
        }
    }
}

EOF

$t->run_daemon(\&fastcgi_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

like(http_get('/'), qr!^HTTP/1.1 200 !s, 'status 200');
like(http_get('/600'), qr!^HTTP/1.1 600 !s, 'status 600 non-standard');

like(http_get('/status-line'), qr!^HTTP/1.1 200 !s, 'status line ignored');
like(http_get('/status-no-text'), qr!^HTTP/1.1 204 !s, 'status header no text');

like(http_get('/no-status'), qr!^HTTP/1.1 200 !s, 'default status');
like(http_get('/no-status-location'), qr!^HTTP/1.1 302 !s,
	'default status with location');

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.29.1');

# 1xx responses are ignored since 1.29.1, and 101 (Switching Protocols)
# is rejected

like(http_get('/100'), qr!^HTTP/1.1 200 .*X-Upstream-Status: 200!s,
	'status 100 ignored');
like(http_get('/103'), qr!^HTTP/1.1 200 !s, 'status 103 ignored');

like(http_get('/101'), qr!^HTTP/1.1 502 !s, 'status 101 rejected');
like(http_get('/101-no-text'), qr!^HTTP/1.1 502 !s, 'status 101 rejected');

like(http_get('/001'), qr!^HTTP/1.1 502 !s, 'status 001 rejected');

}

###############################################################################

sub fastcgi_daemon {
	my $socket = FCGI::OpenSocket('127.0.0.1:' . port(8081), 5);
	my $request = FCGI::Request(\*STDIN, \*STDOUT, \*STDERR, \%ENV,
		$socket);

	my ($uri, $head);

	while( $request->Accept() >= 0 ) {
		$uri = $ENV{REQUEST_URI};

		if ($uri eq '/') {
			print "Status: 200 OK\n\n";

		} elsif ($uri eq '/600') {
			print "Status: 600 Non-standard\n\n";

		} elsif ($uri eq '/status-line') {
			print "HTTP/1.0 204 No content\n\n";

		} elsif ($uri eq '/status-no-text') {
			print "Status: 204\n\n";

		} elsif ($uri eq '/no-status') {
			print "Content-Type: text/html\n\n";

		} elsif ($uri eq '/no-status-location') {
			print "Location: /foobar\n\n";

		} elsif ($uri eq '/100') {
			print "Status: 100 Continue\n\n";
			print "Status: 200 OK\n\n";

		} elsif ($uri eq '/103') {
			print "Status: 103 Early Hints\n";
			print "Link: </foobar>\n\n";
			print "Status: 200 OK\n\n";

		} elsif ($uri eq '/101') {
			print "Status: 101 Switching Protocols\n\n";

		} elsif ($uri eq '/101-no-text') {
			print "Status: 101\n\n";

		} elsif ($uri eq '/001') {
			print "Status: 001 Invalid\n\n";
			print "Status: 200 OK\n\n";
		}
	}

	FCGI::CloseSocket($socket);
}

###############################################################################
