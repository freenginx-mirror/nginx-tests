#!/usr/bin/perl

# (C) Maxim Dounin
# (C) Andrey Zelenkov
# (C) Nginx, Inc.

# Tests for geoip module with MMDB databases.

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

my $t = Test::Nginx->new()->has(qw/http http_geoip/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    geoip_proxy    127.0.0.1/32;

    geoip_country  test.mmdb;
    geoip_city     test.mmdb;
    geoip_org      test.mmdb;

    geoip_set      $asn  test.mmdb  autonomous_system_number;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            add_header X-Country-Code      $geoip_country_code;
            add_header X-Country-Code3     $geoip_country_code3:none;
            add_header X-Country-Name      $geoip_country_name;

            add_header X-Area-Code         $geoip_area_code:none;
            add_header X-C-Continent-Code  $geoip_city_continent_code;
            add_header X-C-Country-Code    $geoip_city_country_code;
            add_header X-C-Country-Code3   $geoip_city_country_code3:none;
            add_header X-C-Country-Name    $geoip_city_country_name;
            add_header X-Dma-Code          $geoip_dma_code;
            add_header X-Latitude          $geoip_latitude;
            add_header X-Longitude         $geoip_longitude;
            add_header X-Region            $geoip_region;
            add_header X-Region-Name       $geoip_region_name;
            add_header X-City              $geoip_city;
            add_header X-Postal-Code       $geoip_postal_code;

            add_header X-Org               $geoip_org;

            add_header X-ASN               $asn;
        }
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

$t->write_file('index.html', '');
$t->try_run('no geoip mmdb')->plan(17);

###############################################################################

my $r = http_get('/');

like($r, qr/X-Country-Code: RU/, 'geoip country code');
like($r, qr/X-Country-Code3: :none/, 'geoip country code 3');
like($r, qr/X-Country-Name: Russian Federation/, 'geoip country name');

like($r, qr/X-Area-Code: :none/, 'geoip area code');
like($r, qr/X-C-Continent-Code: EU/, 'geoip city continent code');
like($r, qr/X-C-Country-Code: RU/, 'geoip city country code');
like($r, qr/X-C-Country-Code3: :none/, 'geoip city country code 3');
like($r, qr/X-C-Country-Name: Russian Federation/, 'geoip city country name');
like($r, qr/X-Dma-Code: 0/, 'geoip dma code');
like($r, qr/X-Latitude: 55.7543/, 'geoip latitude');
like($r, qr/X-Longitude: 37.6202/, 'geoip longitude');
like($r, qr/X-Region: MOW/, 'geoip region');
like($r, qr/X-Region-Name: Moscow/, 'geoip region name');
like($r, qr/X-City: Moscow/, 'geoip city');
like($r, qr/X-Postal-Code: 119034/, 'geoip postal code');

like($r, qr/X-Org: freenginx.org/, 'geoip org');

like($r, qr/X-ASN: 64511/, 'geoip set asn');

###############################################################################
