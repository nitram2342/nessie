#!/usr/bin/perl

use strict;
use XML::Simple;
use Data::Dumper;
use Getopt::Long;


my $sort_key = 'severity';
my @files;
my $help = 0;

my @sort_keys = qw(severity port protocol svc_name pluginFamily pluginName synopsis);

GetOptions ("sort=s" => \$sort_key,
	    "files=s{,}" => \@files,
	    "help" => \$help);


if($help) {
    print 
	"usage: $0 [ <options> ]\n\n",
        "  Options: \n",
	"  --help                         - help screen\n",
	"  --files <file1> [... <fileN> ] - nessus files to read\n",
	"  --sort  <sort-key>             - sort results (default: severity, case sensitive}\n",
	"\n",
	"  Sort keys: @sort_keys)\n",
	"\n\n";
    exit;

}

#
# check sort key
#
foreach my $sk (@sort_keys) {
    if(lc($sk) eq lc($sort_key)) {
	$sort_key = $sk;
    }
}



#
# collect data
#

my @results;

foreach my $file (@ARGV) {

    my $ref = XMLin($file, ForceArray => ['ReportHost', 'ReportItem'] );

    my @host_addresses = keys %{$ref->{Report}->{ReportHost}};
    
    foreach my $host (@host_addresses) {

	my $report_item = $ref->{Report}->{ReportHost}->{$host}->{ReportItem};
    
	foreach my $ri (@$report_item) {
	    $ri->{host} = $host; # XXX
	    push @results, $ri;
	}
    }
}

#
# sort results
#

@results = sort{ $a->{$sort_key} <=> $b->{$sort_key} } @results;

#
# print
#

foreach my $ri (@results) {
    
    my $synopsis = $ri->{synopsis};
    
    $synopsis =~ s!\n! !gs;
    
    printf("%d %15s %5d/%s %15s | %s -- %s\n", 
	   $ri->{severity}, $ri->{host}, $ri->{port}, $ri->{protocol}, 
	   $ri->{svc_name}, $ri->{pluginName}, $synopsis);
}

