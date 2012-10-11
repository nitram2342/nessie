#!/usr/bin/perl

use strict;
use XML::Simple;
use Data::Dumper;

my $file = "/home/martin/Downloads/nessus_report_targets_whitelist_enumerated_batchac.nessus";

foreach my $file (@ARGV) {
    show($file);
}

sub show {
    my $file = shift;

    my $ref = XMLin($file, ForceArray => ['ReportHost', 'ReportItem'] );

    
    my @host_addresses = keys %{$ref->{Report}->{ReportHost}};
    
    foreach my $host (@host_addresses) {

#	print Dumper($ref->{Report}->{ReportHost}->{$host});
	
	my $report_item = $ref->{Report}->{ReportHost}->{$host}->{ReportItem};
    
	foreach my $ri (@$report_item) {
	    # print Dumper($ri);
	    
	    my $severity = $ri->{severity};
	    my $port = $ri->{port};
	    my $protocol = $ri->{protocol};
	    my $svc_name = $ri->{svc_name};
	    my $pluginFamily = $ri->{pluginFamily};
	    my $pluginName = $ri->{pluginName};
	    my $synopsis = $ri->{synopsis};
	    
	    $synopsis =~ s!\n! !gs;
	    
	    printf("%d %15s %5d/%s %15s | %s -- %s\n", $severity, $host, $port, $protocol, $svc_name, $pluginName, $synopsis);
	}
    }
}
