#!/usr/bin/perl

# (C) Maxim Dounin
# (C) Sergey Kandaurov
# (C) Nginx, Inc.

# Tests for mp4 module, various bad mp4 files.

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

my $t = Test::Nginx->new()->has(qw/http mp4/)->plan(1)
	->write_file_expand('nginx.conf', <<'EOF');

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
            mp4;
        }
    }
}

EOF

# chunk offset in stco/co64 atom beyond the end of file

my $bad_co64 = <<'EOF';
00000000:  00 00 00 1c 66 74 79 70  69 73 6f 6d 00 00 02 00  |....ftypisom....|
00000000:  69 73 6f 6d 69 73 6f 32  6d 70 34 31              |isomiso2mp41|
00000000:  00 00 00 08 6d 64 61 74                           |....mdat|
00000000:  00 00 00 94 6d 6f 6f 76                           |....moov|
00000000:  00 00 00 8c 74 72 61 6b                           |....trak|
00000000:  00 00 00 84 6d 64 69 61                           |....mdia|
00000000:  00 00 00 7c 6d 69 6e 66                           |....minf|
00000000:  00 00 00 74 73 74 62 6c                           |....stbl|
00000000:  00 00 00 18 73 74 74 73  00 00 00 00 00 00 00 01  |....stts........|
00000000:  00 00 03 3a 00 00 04 00                           |........|
00000000:  00 00 00 28 73 74 73 63  00 00 00 00 00 00 00 01  |....stsc........|
00000000:  00 00 00 01 ff ff ff ff  00 00 00 00              |............|
00000000:  00 00 00 02 ff ff ff ff  00 00 00 00              |............|
00000000:  00 00 00 14 73 74 73 7a  00 00 00 00 00 00 05 a9  |....stsz........|
00000000:  00 00 03 3b                                       |....|
00000000:  00 00 00 18 63 6f 36 34  00 00 00 00 00 00 00 01  |....co64........|
00000000:  ff ff ff ff f0 0f fb e7                           |........|
EOF

$t->write_file('bad_co64.mp4', unhex($bad_co64));

$t->run();

###############################################################################

like(http_get("/bad_co64.mp4?start=0.5"), qr/500 Internal/,
	'co64 chunk after eof');

###############################################################################

sub unhex {
	my ($input) = @_;
	my $buffer = '';

	for my $l ($input =~ m/:  +((?:[0-9a-f]{2,4} +)+) /gms) {
		for my $v ($l =~ m/[0-9a-f]{2}/g) {
			$buffer .= chr(hex($v));
		}
	}

	return $buffer;
}

###############################################################################
