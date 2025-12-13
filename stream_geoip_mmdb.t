#!/usr/bin/perl

# (C) Maxim Dounin
# (C) Andrey Zelenkov
# (C) Nginx, Inc.

# Tests for stream geoip module with MMDB databases.

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket qw/ $CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/stream stream_geoip stream_return/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    %%TEST_GLOBALS_STREAM%%

    geoip_country  test.mmdb;
    geoip_city     test.mmdb;
    geoip_org      test.mmdb;

    geoip_set      $asn  test.mmdb  autonomous_system_number;

    server {
        listen  127.0.0.1:8080;
        return  "country_code:$geoip_country_code
                 country_code3:$geoip_country_code3:none
                 country_name:$geoip_country_name

                 area_code:$geoip_area_code:none
                 city_continent_code:$geoip_city_continent_code
                 city_country_code:$geoip_city_country_code
                 city_country_code3:$geoip_city_country_code3:none
                 city_country_name:$geoip_city_country_name
                 dma_code:$geoip_dma_code
                 latitude:$geoip_latitude
                 longitude:$geoip_longitude
                 region:$geoip_region
                 region_name:$geoip_region_name
                 city:$geoip_city
                 postal_code:$geoip_postal_code

                 org:$geoip_org

                 asn:$asn";
    }
}

EOF

my $d = $t->testdir();

# MMDB format specification:
# https://github.com/maxmind/MaxMind-DB/blob/main/MaxMind-DB-spec.md

my $data = '';

# binary search tree
# just one node (two records), 32-bit records

$data .= pack('NN', 17, 17);

# data section

$data .= pack('x16');

$data .= pack("B8", "11101000");

$data .= pack("B8A*", "01011000", "autonomous_system_number");
$data .= pack("B8N", "11000100", 64511);

$data .= pack("B8CA*", "01011101", 30 - 29, "autonomous_system_organization");
$data .= pack("B8A*", "01001101", "freenginx.org");

$data .= pack("B8A*", "01000111", "country");
$data .= pack("B8", "11100010");
$data .= pack("B8A*", "01001000", "iso_code");
$data .= pack("B8A*", "01000010", "RU");
$data .= pack("B8A*", "01000101", "names");
$data .= pack("B8", "11100001");
$data .= pack("B8A*", "01000010", "en");
$data .= pack("B8A*", "01010010", "Russian Federation");

$data .= pack("B8A*", "01001001", "continent");
$data .= pack("B8", "11100001");
$data .= pack("B8A*", "01000100", "code");
$data .= pack("B8A*", "01000010", "EU");

$data .= pack("B8A*", "01001100", "subdivisions");
$data .= pack("B8C", "00000001", 11 - 7);
$data .= pack("B8", "11100010");
$data .= pack("B8A*", "01001000", "iso_code");
$data .= pack("B8A*", "01000011", "MOW");
$data .= pack("B8A*", "01000101", "names");
$data .= pack("B8", "11100001");
$data .= pack("B8A*", "01000010", "en");
$data .= pack("B8A*", "01000110", "Moscow");

$data .= pack("B8A*", "01000100", "city");
$data .= pack("B8", "11100001");
$data .= pack("B8A*", "01000101", "names");
$data .= pack("B8", "11100001");
$data .= pack("B8A*", "01000010", "en");
$data .= pack("B8A*", "01000110", "Moscow");

$data .= pack("B8A*", "01000110", "postal");
$data .= pack("B8", "11100001");
$data .= pack("B8A*", "01000100", "code");
$data .= pack("B8A*", "01000110", "119034");

$data .= pack("B8A*", "01001000", "location");
$data .= pack("B8", "11100011");
$data .= pack("B8A*", "01001000", "latitude");
$data .= pack("B8d>", "01101000", 55.7543);
$data .= pack("B8A*", "01001001", "longitude");
$data .= pack("B8d>", "01101000", 37.6202);
$data .= pack("B8A*", "01001010", "metro_code");
$data .= pack("B8C", "10100001", 0);

# metadata

$data .= "\xab\xcd\xefMaxMind.com";

$data .= pack("B8", "11101001");
$data .= pack("B8A*", "01001010", "node_count");
$data .= pack("B8C", "11000001", 1);
$data .= pack("B8A*", "01001011", "record_size");
$data .= pack("B8C", "10100001", 32);
$data .= pack("B8A*", "01001010", "ip_version");
$data .= pack("B8C", "10100001", 6);
$data .= pack("B8A*", "01001101", "database_type");
$data .= pack("B8A*", "01000100", "test");
$data .= pack("B8A*", "01001001", "languages");
$data .= pack("B8B8", "00000001", "00000100");
$data .= pack("B8A*", "01000100", "test");
$data .= pack("B8A*", "01011011", "binary_format_major_version");
$data .= pack("B8C", "10100001", 2);
$data .= pack("B8A*", "01011011", "binary_format_minor_version");
$data .= pack("B8C", "10100001", 0);
$data .= pack("B8A*", "01001011", "build_epoch");
$data .= pack("B8B8C", "00000001", "00000010", 1);
$data .= pack("B8A*", "01001011", "description");
$data .= pack("B8", "11100000");

$t->write_file('test.mmdb', $data);

$t->try_run('no geoip mmdb')->plan(17);

###############################################################################

my %data = stream('127.0.0.1:' . port(8080))->read() =~ /(\w+):(.*)/g;

is($data{country_code}, 'RU', 'geoip country code');
is($data{country_code3}, ':none', 'geoip country code 3');
is($data{country_name}, 'Russian Federation', 'geoip country name');

is($data{area_code}, ':none', 'geoip area code');
is($data{city_continent_code}, 'EU', 'geoip city continent code');
is($data{city_country_code}, 'RU', 'geoip city country code');
is($data{city_country_code3}, ':none', 'geoip city country code 3');
is($data{city_country_name}, 'Russian Federation', 'geoip city country name');
is($data{dma_code}, 0, 'geoip dma code');
is($data{latitude}, 55.7543, 'geoip latitude');
is($data{longitude}, 37.6202, 'geoip longitude');
is($data{region}, 'MOW', 'geoip region');
is($data{region_name}, 'Moscow', 'geoip region name');
is($data{city}, 'Moscow', 'geoip city');
is($data{postal_code}, 119034, 'geoip postal code');

is($data{org}, 'freenginx.org', 'geoip org');

is($data{asn}, '64511', 'geoip set asn');

###############################################################################
