#!/usr/bin/perl

use Nmap::Parser;
use Getopt::Long;
use strict;

my ($file_xml, $file_out, $help);
my @ports;

my %host_matches;

GetOptions("xml=s"     => \$file_xml,
	   "out=s"     => \$file_out,
	   "help"      => \$help,
	   "port=i{,}" => \@ports);

if($help or !defined($file_xml)) {
    print 
	"\n",
	"usage: $0 [ <options> ] \n\n",
        "  Options: \n",
	"  --xml <nmap-file>                     - The nmap file to parse\n",
	"  --out <text-file>                     - Write active hosts to this file\n",
	"  --port <port-num> [ ... <port-num> ]  - Filter by hosts that have this/these port(s) open\n",
	"\n";
    exit;
}

my $np = new Nmap::Parser;
$np->parsefile($file_xml);

foreach my $adr ($np->get_ips("up")) {
    my $h = $np->get_host($adr);

    if($#ports == -1) {
	    $host_matches{$adr} = 1;
    }
    else {
	foreach my $p_nr (@ports) {
	    if($h->tcp_port_state($p_nr)) {
		$host_matches{$adr} = 1;
	    }
	}
    }
}

if(defined $file_out) {
    open(OUTFILE, "> $file_out") or die "can't write out file $file_out: $!\n";
}
else {
    *OUTFILE = *STDOUT;
}

foreach my $adr (keys %host_matches) {
    print OUTFILE $adr,"\n";
}

if(defined($file_out)) {
    close(OUTFILE);
}
