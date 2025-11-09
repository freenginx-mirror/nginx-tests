#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for nginx xslt filter module, various entities.

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

my $t = Test::Nginx->new()->has(qw/http xslt/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

worker_processes 2;

env XML_CATALOG_FILES;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        default_type text/xml;

        location = /test.xml {
            xslt_stylesheet test.xslt;
            xml_entities entities.dtd;
        }

        location = /network.xml {
            xslt_stylesheet test.xslt;
            xml_entities entities.dtd;
        }

        location = /internal.xml {
            xslt_stylesheet test.xslt;
        }

        location = /internal-public.xml {
            xslt_stylesheet test.xslt;
        }

        location = /enabled.xml {
            xslt_stylesheet test.xslt;
            xml_external_entities on;
        }

        location = /enabled-network.xml {
            xslt_stylesheet test.xslt;
            xml_external_entities on;
        }

        location = /catalog.xml {
            xslt_stylesheet test.xslt;
        }

        location = /catalog-system.xml {
            xslt_stylesheet test.xslt;
        }

        location / {
            # static files
        }
    }
}

EOF

my $d = $t->testdir();
my $port = port(8080);

$t->write_file('test.xslt', <<'EOF');

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="@*|node()">
<xsl:copy>
<xsl:apply-templates select="@*|node()"/>
</xsl:copy>
</xsl:template>

</xsl:stylesheet>

EOF

$t->write_file('entities.dtd', <<EOF);
<!ENTITY simple "simple entity">
<!ENTITY external SYSTEM "external.txt">
<!ENTITY network SYSTEM "http://127.0.0.1:$port/network.txt">
<!ENTITY % placeholder SYSTEM "parameter.dtd">
%placeholder;
EOF

$t->write_file('external.txt', <<EOF);
external entity
EOF

$t->write_file('network.txt', <<EOF);
external network entity
EOF

$t->write_file('parameter.dtd', <<EOF);
<!ENTITY parameter "external parameter entity">
EOF

$t->write_file('network.dtd', <<EOF);
<!ENTITY simple "network dtd should not be loaded">
EOF

# Test file for external DTD subset testing:
# all entities are expected to come from "xml_entities entities.dtd"
# defined in the configuration (and not from "network.dtd", which should
# not be loaded)

$t->write_file('test.xml', <<EOF);
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE root SYSTEM "http://127.0.0.1:$port/network.dtd">
<root>
<node>simple: &simple;</node>
<node>external: &external;</node>
<node>parameter: &parameter;</node>
</root>
EOF

$t->write_file('network.xml', <<EOF);
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE root SYSTEM "http://127.0.0.1:$port/network.dtd">
<root>
<node>simple: &simple;</node>
<node>network: &network;</node>
</root>
EOF

# Test file for internal DTD subset testing:
# entities are defined in the file itself, but external entities should
# not be loaded; note that there is no base URL, so external entities
# use absolute names

$t->write_file('internal.xml', <<EOF);
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE root [
<!ENTITY simple "simple entity">
<!ENTITY external SYSTEM "file://$d/external.txt">
<!ENTITY network SYSTEM "http://127.0.0.1:$port/network.txt">
<!ENTITY % placeholder SYSTEM "file://$d/parameter.dtd">
%placeholder;
]>
<root>
<node>simple: &simple;</node>
<node>external: &external;</node>
<node>network: &network;</node>
<node>parameter: &parameter;</node>
</root>
EOF

$t->write_file('internal-public.xml', <<EOF);
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE root [
<!ENTITY simple "simple entity">
<!ENTITY public PUBLIC "public" "file://$d/external.txt">
]>
<root>
<node>simple: &simple;</node>
<node>public: &public;</node>
</root>
EOF

$t->write_file('enabled.xml', <<EOF);
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE root [
<!ENTITY simple "simple entity">
<!ENTITY external SYSTEM "file://$d/external.txt">
<!ENTITY public PUBLIC "public" "file://$d/external.txt">
<!ENTITY % placeholder SYSTEM "file://$d/parameter.dtd">
%placeholder;
]>
<root>
<node>simple: &simple;</node>
<node>external: &external;</node>
<node>public: &public;</node>
<node>parameter: &parameter;</node>
</root>
EOF

$t->write_file('enabled-network.xml', <<EOF);
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE root [
<!ENTITY simple "simple entity">
<!ENTITY network SYSTEM "http://127.0.0.1:$port/network.txt">
]>
<root>
<node>simple: &simple;</node>
<node>network: &network;</node>
</root>
EOF

# Tests for in-document XML catalogs: these used to be allowed
# by default till libxml2 2.14.0

$ENV{XML_DEBUG_CATALOG} = 1;
$ENV{XML_CATALOG_FILES} = "$d/catalog.system.xml";

$t->write_file('catalog.xml', <<EOF);
<?xml version="1.0" encoding="UTF-8" ?>
<?oasis-xml-catalog catalog="file:///$d/catalog.document.xml" ?>
<!DOCTYPE root [
<!ENTITY catalog PUBLIC "catalog" "">
]>
<root>
<node>catalog: &catalog;</node>
</root>
EOF

$t->write_file('catalog-system.xml', <<EOF);
<?xml version="1.0" encoding="UTF-8" ?>
<?oasis-xml-catalog catalog="file:///$d/catalog.document.xml" ?>
<!DOCTYPE root [
<!ENTITY system PUBLIC "system" "">
]>
<root>
<node>system: &system;</node>
</root>
EOF

$t->write_file('catalog.document.xml', <<EOF);
<?xml version="1.0"?>
<!DOCTYPE catalog PUBLIC "-//OASIS//DTD Entity Resolution XML Catalog V1.0//EN"
"http://www.oasis-open.org/committees/entity/release/1.0/catalog.dtd">
<catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">
  <public publicId="catalog" uri="file:///$d/external.txt" />
</catalog>
EOF

$t->write_file('catalog.system.xml', <<EOF);
<?xml version="1.0"?>
<!DOCTYPE catalog PUBLIC "-//OASIS//DTD Entity Resolution XML Catalog V1.0//EN"
"http://www.oasis-open.org/committees/entity/release/1.0/catalog.dtd">
<catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">
  <public publicId="system" uri="file:///$d/external.txt" />
</catalog>
EOF

$t->try_run('no xml_external_entities')->plan(16);

###############################################################################

my $r;

# External DTD subset, all entities from "xml_entities entities.dtd"
# in the configuration

$r = http_get('/test.xml');

like($r, qr/simple: simple entity/, 'simple entity');
like($r, qr/external: external entity/, 'external entity');
like($r, qr/parameter: external parameter entity/,
	'external parameter entity');

# Network entity tested separately, as attempt to load it results
# in parser error in some libxml2 versions (for example, libxml2 2.9.7
# as seen on Rocky Linux 8)

$r = http_get('/network.xml');

unlike($r, qr/network: external network entity/,
	'external network entity not loaded');

# Internal DTD subset, no external entities are loaded

$r = http_get('/internal.xml');

like($r, qr/simple: simple entity/, 'internal subset, simple entity');
unlike($r, qr/external: external entity/,
	'internal subset, external entity not loaded');
unlike($r, qr/network: external network entity/,
	'internal subset, external network entity not loaded');
unlike($r, qr/parameter: external parameter entity/,
	'internal subset, external parameter entity not loaded');

# Public entity tested separately, as attempt to load it results
# in parser error in some libxml2 versions

$r = http_get('/internal-public.xml');

unlike($r, qr/public: external entity/,
	'internal subset, external public entity not loaded');

# In-document XML catalogs

$r = http_get('/catalog.xml');

unlike($r, qr/catalog: external entity/,
	'internal subset, external entity via document catalog not loaded');

$r = http_get('/catalog-system.xml');

like($r, qr/system: external entity/,
	'internal subset, external entity via system catalog');

# Re-enabled external entities in internal DTD subset with
# the xml_external_entities directive

$r = http_get('/enabled.xml');

like($r, qr/simple: simple entity/, 'internal subset, simple entity');
like($r, qr/external: external entity/,
	'internal subset, external entity enabled');
like($r, qr/public: external entity/,
	'internal subset, external public entity enabled');

# External parameter entities in internal DTD subset are broken in
# libxml2 2.11.x (but work fine in 2.10.x and 2.12.x), hence TODO

TODO: {
local $TODO = 'broken in libxml2 2.11.x'
	unless $r =~ /parameter: external parameter entity/;

like($r, qr/parameter: external parameter entity/,
	'internal subset, external parameter entity enabled');

}

$r = http_get('/enabled-network.xml');

unlike($r, qr/network: external network entity/,
	'internal subset, external network entity not loaded anyway');

###############################################################################
