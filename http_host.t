#!/usr/bin/perl

# (C) Maxim Dounin
# (C) Valentin Bartenev

# Tests for host parsing in requests.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_content /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http rewrite/)->plan(74);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen  127.0.0.1:8080;
        server_name  localhost;

        location / {
            return  200  $host;
        }
    }
}

EOF

$t->run();

###############################################################################

# host
# host:port
# host.
# host.:port
# HOST
# HOST:port
# host09
# ho-st
# _host

is(hh('example.com'), 'example.com', 'host');
is(rl('example.com'), 'example.com', 'host in request line');

is(hh('example.com:80'), 'example.com', 'host:port');
is(rl('example.com:80'), 'example.com', 'host:port in request line');

is(hh('example.com.'), 'example.com', 'host with dot');
is(rl('example.com.'), 'example.com', 'host with dot in request line');

is(hh('example.com.:80'), 'example.com', 'host:port with dot');
is(rl('example.com.:80'), 'example.com', 'host:port with dot in request line');

is(hh('EXAMPLE.com'), 'example.com', 'host with uppercase');
is(rl('EXAMPLE.com'), 'example.com', 'host with uppercase in request line');

is(hh('EXAMPLE.com:80'), 'example.com', 'host:port with uppercase');
is(rl('EXAMPLE.com:80'), 'example.com',
	'host:port with uppercase in request line');

is(hh('foo09.example.com'), 'foo09.example.com', 'host with digits');
is(rl('foo09.example.com'), 'foo09.example.com',
	'host with digits in request line');

is(hh('foo-bar.example.com'), 'foo-bar.example.com', 'host with dash');
is(rl('foo-bar.example.com'), 'foo-bar.example.com',
	'host with dash in request line');

is(hh('_foo.example.com'), '_foo.example.com', 'host with underscore');

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.29.1');

is(rl('_foo.example.com'), '_foo.example.com',
	'host with underscore in request line');

}

# all characters permitted by RFC 3986
# (unreserved, pct-encoded, sub-delims)

is(hh(q{-._~!$&'()*+,;=%25.example.com}), q{-._~!$&'()*+,;=%25.example.com},
	'host with sub-delims');

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.29.1');

is(rl(q{-._~!$&'()*+,;=%25.example.com}), q{-._~!$&'()*+,;=%25.example.com},
	'host with sub-delims in request line');

}

# ip
# ip:port
# ipv6
# ipv6:port
# ipv6-v4mapped
# ipv6-v4mapped:port

is(hh('192.0.2.1'), '192.0.2.1', 'ip');
is(rl('192.0.2.1'), '192.0.2.1', 'ip in request line');

is(hh('192.0.2.1:80'), '192.0.2.1', 'ip');
is(rl('192.0.2.1:80'), '192.0.2.1', 'ip:port in request line');

is(hh('[2001:db8::1]'), '[2001:db8::1]', 'ipv6');
is(rl('[2001:db8::1]'), '[2001:db8::1]', 'ipv6 in request line');

is(hh('[2001:db8::1]:80'), '[2001:db8::1]', 'ipv6:port');
is(rl('[2001:db8::1]:80'), '[2001:db8::1]', 'ipv6:port in request line');

is(hh('[2001:DB8::1]'), '[2001:db8::1]', 'ipv6 with uppercase');
is(rl('[2001:DB8::1]'), '[2001:db8::1]',
	'ipv6 with uppercase in request line');

is(hh('[2001:DB8::1]:80'), '[2001:db8::1]', 'ipv6:port with uppercase');
is(rl('[2001:DB8::1]:80'), '[2001:db8::1]',
	'ipv6:port with uppercase in request line');

is(hh('[::ffff:192.0.2.1]'), '[::ffff:192.0.2.1]', 'ipv6 v4mapped');
is(rl('[::ffff:192.0.2.1]'), '[::ffff:192.0.2.1]',
	'ipv6 v4mapped in request line');

is(hh('[::ffff:192.0.2.1]:80'), '[::ffff:192.0.2.1]', 'ipv6:port v4mapped ');
is(rl('[::ffff:192.0.2.1]:80'), '[::ffff:192.0.2.1]',
	'ipv6:port v4mapped in request line');

# ipv6 with zoneid, RFC 6874

is(hh('[2001:db8::1%25en1]'), '[2001:db8::1%25en1]', 'ipv6 zoneid');
is(hh('[2001:db8::1%25en1]:80'), '[2001:db8::1%25en1]', 'ipv6:port zoneid');

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.29.1');

is(rl('[2001:db8::1%25en1]'), '[2001:db8::1%25en1]',
	'ipv6 zoneid in request line');
is(rl('[2001:db8::1%25en1]:80'), '[2001:db8::1%25en1]',
	'ipv6:port zoneid in request line');
}

# ipvfuture

is(hh('[v0.1azAZ.!$&\'()*+,;=-._~:]'), '[v0.1azaz.!$&\'()*+,;=-._~:]',
	'ipvfuture');
is(rl('[v0.1azAZ.!$&\'()*+,;=-._~:]'), '[v0.1azaz.!$&\'()*+,;=-._~:]',
	'ipvfuture in request line');

is(hh('[v0.1azAZ.!$&\'()*+,;=-._~:]:80'), '[v0.1azaz.!$&\'()*+,;=-._~:]',
	'ipvfuture:port');
is(rl('[v0.1azAZ.!$&\'()*+,;=-._~:]:80'), '[v0.1azaz.!$&\'()*+,;=-._~:]',
	'ipvfuture:port in request line');

# various invalid cases:
#
# example/com (only make sense in host header)
# example\com
# example..com
# example.com:port:port
# example.com:invalid_port
# [ipv6/foo]
# [ipvfuture/foo]
# [ipv6..foo]
# [ipvfuture..foo]
# [ipv6 (no closing "]")
# [ipvfuture (no closing "]")

like(hh('example/com'), qr/ 400 /, 'host with slash');

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.29.1')
	or $^O eq 'MSWin32';

like(hh('example\com'), qr/ 400 /, 'host with backslash');

}

like(rl('example\com'), qr/ 400 /, 'host with backslash in request line');

like(hh('example..com'), qr/ 400 /, 'host with double dots');
like(rl('example..com'), qr/ 400 /, 'host with double dots in request line');

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.29.1');

like(hh('example.com:80:80'), qr/ 400 /, 'host with two ports');

}

like(rl('example.com:80:80'), qr/ 400 /,
	'host with two ports in request line');

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.29.1');

like(hh('example.com:foo'), qr/ 400 /, 'host with invalid port');

}

like(rl('example.com:foo'), qr/ 400 /,
	'host with invalid port in request line');

like(hh('[2001:db8::1/2]'), qr/ 400 /, 'ipv6 with slash');
like(rl('[2001:db8::1/2]'), qr/ 400 /,
	'ipv6 with slash in request line');

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.29.1')
	or $^O eq 'MSWin32';

like(hh('[2001:db8::1\2]'), qr/ 400 /, 'ipv6 with backslash');

}

like(rl('[2001:db8::1\2]'), qr/ 400 /, 'ipv6 with backslash in request line');

like(hh('[2001:db8::1..2]'), qr/ 400 /, 'ipv6 with double dots');
like(rl('[2001:db8::1..2]'), qr/ 400 /,
	'ipv6 with double dots in request line');

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.29.1');

like(hh('[2001:db8::1'), qr/ 400 /, 'ipv6 without closing bracket');

}

like(rl('[2001:db8::1'), qr/ 400 /,
	'ipv6 without closing bracket in request line');

like(hh('[v0.1/2]'), qr/ 400 /, 'ipvfuture with slash');
like(rl('[v0.1/2]'), qr/ 400 /, 'ipvfuture with slash in request line');

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.29.1')
	or $^O eq 'MSWin32';

like(hh('[v0.1\2]'), qr/ 400 /, 'ipvfuture with backslash');

}

like(rl('[v0.1\2]'), qr/ 400 /, 'ipvfuture with backslash in request line');

like(hh('[v0.1..2]'), qr/ 400 /, 'ipvfuture with double dots');
like(rl('[v0.1..2]'), qr/ 400 /, 'ipvfuture with double dots in request line');

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.29.1');

like(hh('[v0.1'), qr/ 400 /, 'ipvfuture without closing bracket');

}

like(rl('[v0.1'), qr/ 400 /,
	'ipvfuture without closing bracket in request line');

# control characters

like(hh("example.com\x02"), qr/ 400 /, 'host with control chars');
like(rl("example.com\x02"), qr/ 400 /,
	'host with control chars in request line');

# non-ascii characters

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.29.1');

like(hh("example.com\xff"), qr/ 400 /, 'host with non-ascii chars');

}

like(rl("example.com\xff"), qr/ 400 /,
	'host with non-ascii chars in request line');

# multiple host headers

like(hh("localhost\nHost: again"), qr/ 400 /, 'duplicate host');

###############################################################################

sub hh {
	my ($host) = @_;
	my $r = http(<<EOF);
GET / HTTP/1.0
Host: $host

EOF
	return ($r =~ m/ 200 /) ? http_content($r) : $r;
}

sub rl {
	my ($host) = @_;
	my $r = http(<<EOF);
GET http://$host/ HTTP/1.0

EOF
	return ($r =~ m/ 200 /) ? http_content($r) : $r;
}

###############################################################################
