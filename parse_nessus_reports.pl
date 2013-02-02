#!/usr/bin/perl

use FindBin; 
use lib $FindBin::Bin;

use strict;
use XML::Simple;
use Data::Dumper;
use Getopt::Long;
use Text::ASCIITable;
use NessieBrowser;
use Data::Diver qw/Dive/;

my @files;
my @sub_files;
my $help = 0;
my $severity = 0;
my $_dump = 0;


GetOptions ("files=s{,}" => \@files,
	    "sub:s{,}" => \@sub_files,
	    "severity=i" => \$severity,
	    "help" => \$help,
	    "dump" => \$_dump);

if($help) {
    print 
	"usage: $0 [ <options> ]\n\n",
        "  Options: \n",
	"  --help                         - help screen\n",
	"  --dump                         - just dump, no interaction\n",
	"  --files <file1> [... <fileN> ] - nessus files to read\n",
	"  --sub   <file1> [... <fileN> ] - subtract these findings\n",
	"  --severity <level>             - minium severity\n",
	"\n",
	"\n\n";
    exit;

}


my $results = get_results($severity, @files);
my $sub_results = get_results($severity, @sub_files);
$results = sub_results($results, $sub_results);
$results = sort_results($results);
if($_dump) {
    print_results($results);
}
else {
    browse_results($results);
}


sub sub_results {
    my ($all, $minus) = @_;
    my @results = grep { not result_is_in($_, $minus) } @$all;
    return \@results;
}

sub result_is_in {
    my ($item, $set) = @_;
    foreach my $t (@$set) {
	if(($item->{_host} eq $t->{_host}) and 
	   ($item->{port} eq $t->{port}) and
	   ($item->{pluginName} eq $t->{pluginName}) and
	   ($item->{protocol} eq $t->{protocol}) and
	   ($item->{severity} eq $t->{severity}) ) {
	    return 1;
	}
    }
    return 0;
}

#
# sort results
#

sub sort_results {
    my $results = shift;

    my @results = sort{ ($b->{severity} <=> $a->{severity}) || 
			    ($b->{pluginName} cmp $a->{pluginName}) ||
			    ($a->{_host} cmp $b->{_host}) ||
			    ($a->{port} <=> $b->{port}) ||
			    ($a->{protocol} cmp $b->{protocol})
    } @$results;
    return \@results;
}

#
# print
#

sub print_results {
    my $results = shift;

    my $tb = Text::ASCIITable->new();
    $tb->setCols(qw(Sv. Host Port Service Xplt Plugin OS));
    $tb->setColWidth('Service', 10);
    $tb->alignCol('Host', 'left');
    $tb->alignCol('Port', 'right');

    foreach my $ri (@$results) {
    
#	my $synopsis = $ri->{synopsis};
#	$synopsis =~ s!\n! !gs;

	$tb->addRow($ri->{severity},
		    $ri->{_host},
		    ($ri->{port} ne '0') ? ( $ri->{port} . ' ' . $ri->{protocol}) : '',
		    $ri->{svc_name},
		    (lc($ri->{exploit_available}) eq 'true' ? 'X' : ''),
		    $ri->{pluginName}, $ri->{os});
    }
    print $tb->draw(['','','-','-'], 
		    ['','',' '],
		    ['-','-','-','-'], 
		    ['','',' '],
		    ['','','-','-'],
		    ['','',' ']);

}


sub browse_results {
    my $report_items = shift;
    my $browser = NessieBrowser->new($report_items);
    $browser->run();
}

sub to_uri {
    my $ri = shift;
    if($ri->{port} == 80 || $ri->{svc_name} =~ m!www!) { return "http://$ri->{host}:$ri->{port}/"; }
    if($ri->{port} == 443) { return "https://$ri->{host}:$ri->{port}/"; }
    if($ri->{port} == 21) { return "ftp://$ri->{host}:$ri->{port}/"; }
}

#
# collect data
#

sub get_results {
    my $severity = shift;
    my @files = @_;

    my @results;

    foreach my $file (@files) {
	
	my $ref = XMLin($file, ForceArray => ['ReportHost', 'ReportItem'] );
	
	my @host_addresses = keys %{$ref->{Report}->{ReportHost}};
	
	foreach my $host (@host_addresses) {

	    my $host_item = Dive($ref, qw(Report ReportHost), $host);

	    
	    my $report_item = Dive($ref, qw(Report ReportHost), $host, qw(ReportItem));
	    foreach my $ri (@$report_item) {
		if($ri->{severity} >= $severity) {
		    $ri->{_host} = $host;
		    $ri->{_ReportHost} = Dive($ref, qw(Report ReportHost), $host);
		    push @results, $ri;
		}
	    }
	}
    }
    return \@results;
}
