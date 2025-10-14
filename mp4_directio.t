#!/usr/bin/perl

# (C) Maxim Dounin

# Test for directio support in mp4 module.

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

my $t = Test::Nginx->new()->has(qw/http mp4/)->has_daemon('ffmpeg')
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
            open_file_cache max=10;
            directio 0;
        }
    }
}

EOF

plan(skip_all => 'no lavfi')
	unless grep /lavfi/, `ffmpeg -loglevel quiet -formats`;
system('ffmpeg -nostdin -loglevel quiet -y '
	. '-f lavfi -i testsrc=duration=10:size=320x200:rate=15 '
	. '-g 15 -c:v mpeg4 '
	. "${\($t->testdir())}/test.mp4") == 0
	or die "Can't create mp4 file: $!";

$t->run()->plan(2);

###############################################################################

# mp4 module uses unaligned reads while parsing mp4 file, though
# failed to disable directio if a file with directio enabled was
# returned from open file cache

like(http_get('/test.mp4?start=1.0'), qr/ 200 /, 'mp4 directio first');

TODO: {
local $TODO = 'not yet' unless $t->has_version('1.29.0') or $^O ne 'linux';

like(http_get('/test.mp4?start=1.0'), qr/ 200 /, 'mp4 directio cached');

}

###############################################################################
