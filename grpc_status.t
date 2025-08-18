#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for grpc backend returning various status codes.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
	->has(qw/http grpc/)->plan(12);

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

        grpc_read_timeout 10s;
        add_header X-Upstream-Status $upstream_status;

        location / {
            grpc_pass grpc://127.0.0.1:8081;
        }
    }
}

EOF

$t->run_daemon(\&grpc_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

###############################################################################

like(http_get('/'), qr!^HTTP/1.1 200 !s, 'status 200');
like(http_get('/600'), qr!^HTTP/1.1 600 !s, 'status 600 non-standard');

like(http_get('/no-status'), qr!^HTTP/1.1 502 !s, 'no status rejected');
like(http_get('/duplicate'), qr!^HTTP/1.1 502 !s, 'duplicate status rejected');
like(http_get('/spaces'), qr!^HTTP/1.1 502 !s, 'status with spaces rejected');
like(http_get('/nonfirst'), qr!^HTTP/1.1 502 !s, 'non first status rejected');

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.29.1');

# 1xx responses are ignored since 1.29.1

like(http_get('/100'), qr!^HTTP/1.1 200 .*X-Upstream-Status: 200!s,
        'status 100 ignored');
like(http_get('/103'), qr!^HTTP/1.1 200 !s, 'status 103 ignored');

}

like(http_get('/100-end-stream'), qr!^HTTP/1.1 502 !s,
	'status 100 with end stream rejected');
like(http_get('/100-many'), qr!^HTTP/1.1 502 !s,
	'status 100 many times rejected');

like(http_get('/101'), qr!^HTTP/1.1 502 !s, 'status 101 rejected');
like(http_get('/001'), qr!^HTTP/1.1 502 !s, 'status 001 rejected');

###############################################################################

sub grpc_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:' . port(8081),
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

 		# preface
		$client->sysread(my $buf, 24) == 24
			or next;

		my $c = Test::Nginx::HTTP2->new(
			1, socket => $client, pure => 1, preface => ""
		)
			or next;

		my $frames = $c->read(all => [{ fin => 4 }]);
		my ($frame) = grep { $_->{type} eq "HEADERS" } @$frames;

		my $sid = $frame->{sid};
		my $uri = $frame->{headers}{':path'};
		my $status;

		if ($uri eq '/') {
			$c->new_stream({ headers => [
				{ name => ':status', value => '200' },
			]}, $sid);

		} elsif ($uri eq '/600') {
			$c->new_stream({ headers => [
				{ name => ':status', value => '600' },
			]}, $sid);

		} elsif ($uri eq '/no-status') {
			$c->new_stream({ headers => [
				{ name => 'foo', value => 'bar' },
			]}, $sid);

		} elsif ($uri eq '/duplicate') {
			$c->new_stream({ headers => [
				{ name => ':status', value => '200' },
				{ name => ':status', value => '204' },
			]}, $sid);

		} elsif ($uri eq '/spaces') {
			$c->new_stream({ headers => [
				{ name => ':status', value => '2 0 0' },
			]}, $sid);

		} elsif ($uri eq '/nonfirst') {
			$c->new_stream({ headers => [
				{ name => 'foo', value => 'bar' },
				{ name => ':status', value => '200' },
			]}, $sid);

		} elsif ($uri eq '/100') {
			$c->new_stream({ body_more => 1, headers => [
				{ name => ':status', value => '100' },
			]}, $sid);
			$c->new_stream({ headers => [
				{ name => ':status', value => '200' },
			]}, $sid);

		} elsif ($uri eq '/100-end-stream') {
			$c->new_stream({ headers => [
				{ name => ':status', value => '100' },
			]}, $sid);
			$c->new_stream({ headers => [
				{ name => ':status', value => '200' },
			]}, $sid);

		} elsif ($uri eq '/100-many') {
			$c->new_stream({ body_more => 1, headers => [
				{ name => ':status', value => '100' },
			]}, $sid)
				for 1..15;
			$c->new_stream({ headers => [
				{ name => ':status', value => '200' },
			]}, $sid);

		} elsif ($uri eq '/103') {
			$c->new_stream({ body_more => 1, headers => [
				{ name => ':status', value => '103' },
			]}, $sid);
			$c->new_stream({ headers => [
				{ name => ':status', value => '200' },
			]}, $sid);

		} elsif ($uri eq '/101') {
			$c->new_stream({ body => 'foo', headers => [
				{ name => ':status', value => '101' },
			]}, $sid);

		} elsif ($uri eq '/001') {
			$c->new_stream({ body => 'foo', headers => [
				{ name => ':status', value => '101' },
			]}, $sid);
		}

		close $client;
	}
}

###############################################################################
