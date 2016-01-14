#!/usr/bin/perl -w
#
# Simple SNMP memory check - version 1.1
#
# Originally written by Corey Henderson
#
# Dual-Licensed - you may choose between:
#
# 1) Public Domain
# 2) WTFPL - see http://sam.zoy.org/wtfpl/
#

use strict;
use warnings;

use constant STATUS_OK => 0;
use constant STATUS_WARN => 1;
use constant STATUS_CRITICAL => 2;
use constant STATUS_UNKNOWN => 3;

my $snmpget = '/usr/bin/snmpget';

my $warn;
my $crit;
my $swap;

use Getopt::Long;

my $result = GetOptions(
	"w=i" => \$warn,
	"c=i" => \$crit,
	"s" => \$swap,
	"h|help" => \&usage,
);

sub usage {
	print "Usage: $0 -w NUM -c NUM [-s] -- [snmpget options]\n";
	print "\t-w\twarning threshhold\n";
	print "\t-c\tcritical threshhold\n";
	print "\t-s\tcheck swap instead of memory\n";
	print "EXAMPLES:\n";
	print "\tsnmp v1:\n";
	print "\t$0 -w 85 -c 95 -- -c community example.com\n";
	print "\tsnmp v3:\n";
	print "\t$0 -w 85 -c 95 -- -v3 -l authPriv -a MD5 -u exampleuser -A \"example password\" example.com\n";
	exit STATUS_UNKNOWN;
}

if (!$warn or !$crit or ($warn and ($warn !~ /^[0-9]+$/ or $warn < 0 or $warn > 100)) or ($crit and ($crit !~ /^[0-9]+$/ or $crit < 0 or $crit > 100))) {
	print "You must supply -w and -c with integer values between 0 and 100\n";
	&usage;
}

map { $_ = '"' . $_ . '"' if $_ =~ / /} @ARGV;
map { $_ = "'" . $_ . "'" if $_ =~ /"/} @ARGV;

my $STR = join(" ", @ARGV);

sub do_snmp {
	my ($OID) = @_;

	my $cmd = $snmpget . " " . $STR . " " . $OID;

	chomp(my $out = `$cmd 2> /dev/null`);

	if ($? != 0) {
		print "SNMP problem - no value returned\n";
		exit STATUS_UNKNOWN;
	}

	my $type;

	my ($jnk, $x) = split / = /, $out, 2;

	if ($x =~ /([a-zA-Z0-9]+): (.*)$/) {
		$type = $1;
		$x = $2;
	}

	return $x;
}

my $check;
my $realPercent;
my $status_str;

if ($swap) {

	$check = "SWAP";

	my $swapFreeOID = '.1.3.6.1.4.1.2021.4.4.0';
	my $swapTotalOID = '.1.3.6.1.4.1.2021.4.3.0';

    # Fix: get rid of last 3 character that was " kB" as they aren't relevant here.
	my $swapTotal = substr(do_snmp($swapTotalOID), 0, -3);

	if (0 == $swapTotal) {
		print "SNMP problem - total swap is zero, is swap enabled on this host?\n";
		exit STATUS_UNKNOWN;
	}

    # Fix: get rid of last 3 character that was " kB" as they aren't relevant here.
	my $swapFree = substr(do_snmp($swapFreeOID), 0, -3);

	$realPercent = (($swapTotal - $swapFree) / $swapTotal) * 100;

    # Enh/Fix: compliance with nagios plugin dev guidelines
    $status_str = "Free => $swapFree Kb, Total => $swapTotal Kb | swap_free=$swapFree;$warn;$crit;;$swapTotal swap_total=$swapTotal;;;;";

} else {

	$check = "MEMORY";

	my $memRealTotalOID = '.1.3.6.1.4.1.2021.4.5.0';
	my $memRealFreeOID = '.1.3.6.1.4.1.2021.4.6.0';
	my $memRealCachedOID = '.1.3.6.1.4.1.2021.4.15.0';
	my $memRealBuffersOID = '.1.3.6.1.4.1.2021.4.14.0';

    # Fix: get rid of last 3 character that was " kB" as they aren't relevant here.
	my $memRealTotal = substr(do_snmp($memRealTotalOID), 0, -3);

	if (0 == $memRealTotal) {
		print "SNMP problem - no value returned\n";
		exit STATUS_UNKNOWN;
	}

    # Fix: get rid of last 3 character that was " kB" as they aren't relevant here.
	my $memRealFree = substr(do_snmp($memRealFreeOID), 0, -3);
	my $memRealCached = substr(do_snmp($memRealCachedOID), 0, -3);
	my $memRealBuffers = substr(do_snmp($memRealBuffersOID), 0, -3);

	my $memRealUsed = $memRealTotal - $memRealFree;

	$realPercent = (($memRealUsed - $memRealBuffers - $memRealCached )/ $memRealTotal) * 100;

    # Enh/Fix: compliance with nagios plugin dev guidelines
    $status_str = "Free => $memRealFree Kb, Total => $memRealTotal Kb, Cached => $memRealCached Kb, Buffered => $memRealBuffers Kb | ram_free=$memRealFree;$warn;$crit;;$memRealTotal ram_total=$memRealTotal;;;; ram_cached=$memRealCached;;;;$memRealTotal ram_buffered=$memRealBuffers;;;;$memRealTotal";

}

my $ret;
my $status;

print "$check ";

if ($realPercent >= $crit) {
	print "CRITICAL";
	$ret = STATUS_CRITICAL;
} elsif ($realPercent >= $warn) {
	print "WARNING";
	$ret = STATUS_WARN;
} else {
	print "OK";
	$ret = STATUS_OK;
}

print ": " . sprintf("%.2f", $realPercent) . " % used; " . $status_str . "\n";

exit $ret

