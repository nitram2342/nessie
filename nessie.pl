#!/usr/bin/perl

print 
    "\n",
    "                              _   _       _a_a       \n",
    "                  _   _     _{.`=`.}_    {/ ''\\_     \n",
    "            _    {.`'`.}   {.'  _  '.}  {|  ._oo)    \n",
    "           { \\  {/ .-. \\} {/  .' '.  \\} {/  |        \n",
    "    ~jgs^~`~^~`~^~`~^~`~^~^~`^~^~`^~^~^~^~^~^~`^~~`  \n",
    " @@@  @@@  @@@@@@@@   @@@@@@   @@@@@@   @@@  @@@@@@@@\n",
    " @@@@ @@@  @@@@@@@@  @@@@@@@  @@@@@@@  @@@@  @@@@@@@@\n",
    " @@!@!@@@  @@!       !@@      !@@     @@@!!  @@!     \n",
    " !@!!@!@!  !@!       !@!      !@!       !@!  !@!     \n",
    " @!@ !!@!  @!!!:!    !!@@!!   !!@@!!    @!@  @!!!:!  \n",
    " !@!  !!!  !!!!!:     !!@!!!   !!@!!!   !@!  !!!!!:  \n",
    " !!:  !!!  !!:            !:!      !:!  !!:  !!:     \n",
    " :!:  !:!  :!:           !:!      !:!   :!:  :!:     \n",
    "  ::   ::   :: ::::  :::: ::  :::: ::   :::   :: ::::\n",
    " ::    :   : :: ::   :: : :   :: : :     ::  : :: :: \n",
    "\n";

$ENV{HTTPS_CA_FILE} = 'ca';

use Getopt::Long;
use Net::Nessus::XMLRPC;
use warnings;
use strict;
use Data::Dumper;
use Nmap::Parser;
#use Nmap::Scanner;
use Config::General;
use File::stat;
use FindBin qw($Bin);

my $help;
my $list_policies;
my $list_scans;
my $list_reports;
my $delete_report;
my $pause_all;
my $resume_all;
my $stop_all;
my $scan;
my $policy;
my $name;
my @targets;
my $file;
my $download;
my $batch_size = 16;
my $wait;

my $server = 'https://127.0.0.1:8834/';
my $user = 'nessus';
my $password;

### parse config

my $config_file = $Bin . "/.nessie";

# check config file permissions and parse the config
if((-f $ENV{HOME}. $config_file) and !(-f $config_file)) {
    $config_file = $ENV{HOME}. $config_file
}

if(-f $config_file) {
    my $mode = stat($config_file)->mode & 07777;
    if($mode == 0600) {
	my $conf = new Config::General(-ConfigFile => $config_file,
				       -DefaultConfig => {user => $user,
							  server => $server,
							  batch_size => $batch_size});
	my %config = $conf->getall();
	$batch_size = $config{batch_size};
	$user = $config{user};
	$password = $config{password};
	$server = $config{server};
    }
    else {
	error_msg(sprintf("Config file $config_file has permissions %o, but it needs 600.", $mode));
    }

}

### evaluate parameters
GetOptions ("list-policies"   => \$list_policies,
	    "list-scans"      => \$list_scans,
	    "list-reports"    => \$list_reports,
	    "delete-report=s" => \$delete_report,
	    "scan"            => \$scan,
	    "name=s"          => \$name,
	    "policy=s"        => \$policy,
	    "targets=s{,}"    => \@targets,
	    "file=s"          => \$file,
	    "wait:s"          => \$wait,
	    "pause"           => \$pause_all,
	    "resume"          => \$resume_all,
	    "stop"            => \$stop_all,
	    "download=s"      => \$download,
	    "batch-size=i"    => \$batch_size,
            "help"            => \$help,
            "server=s"        => \$server,
            "user=s"          => \$user,
            "passwordr=s"     => \$password
);


### login
my $n;
if(not $help) {
    log_msg("Connecting to nessus xmlrpc service at $server.");
    $n = Net::Nessus::XMLRPC->new($server, $user, $password);
    
    error_msg("Cannot login to: " . $n->nurl()) unless ($n->logged_in());
}

#    my $stat = $n->scan_full_status('0bd9ee48-4752-ebd9-5053-2c8f27da16d199527d0fc14a39f1');
#exit;

if($help) {
    print_help();
}
elsif($list_policies) {
    list_policies($n);
}
elsif($list_scans) {
    list_scans($n);
}
elsif($list_reports) {
    list_reports($n);
}
elsif($scan) {

    # check params
    check_param($name, "Please specify a scan name with --name.");
    check_param($policy, "Please specify a policy name with --policy.");

    # determin the policy
    my $policy_id;
    if($policy =~ m!^[\+\-]?\d+$!) {
	log_msg("Treat policy parameter as policy id.");
	$policy_id = $policy;
    }
    else {
	$policy_id = $n->policy_get_id($policy);
    }

    # start scan
    my $scan_id;
    log_msg("Starting a new scan.");

    my @targets_;

    if($#targets > -1) {
	@targets_ = @targets;
    }
    elsif(defined($file)) {

	if($file =~ m!.xml$!) {
	    log_msg("File $file is an nmap file. Looking for active hosts.", 1);
	    @targets_ = parse_nmap_xml($file);
	}
	else {
	    log_msg("File $file is a regular text file. Looking for targets.", 1);
	    @targets_ = parse_targets($file);
	}
	log_msg("File $file defines " .($#targets_ +1) . " targets.", 1);
    }
    else {
	error_msg("don't know what to scan"); # will exit
    }
	    
    if(!batch_scan($n, $policy_id, $name, \@targets_, $wait, $batch_size)) {
	error_msg("Scan failed.");
    }

}
elsif($pause_all) {
    my $ret = $n->scan_pause_all();
    print "ret: @{$ret}\n";
}

elsif($resume_all) {
    my $ret = $n->scan_resume_all();
    print "ret: @{$ret}\n";
}
elsif($stop_all) {
    my $ret = $n->scan_stop_all();
    print "ret: @{$ret}\n";
}
elsif(defined($download) and ($download ne '')) {

    my $err = 0;
    my $ret;

    if($download eq 'all') {
	foreach my $report_id (list_reports($n)) {
	    download_report($n, $report_id, $report_id . ".nessus");
	}
    }
    elsif(is_id($download)) {
	download_report($n, $download, $download . ".nessus");
    }
    else {
	foreach my $report_id (list_reports($n, $download)) {
	    download_report($n, $report_id, $report_id . ".nessus");
	}
    }
   
}
elsif(defined($delete_report) and ($delete_report ne '')) {
    my $err = 0;

    if(is_id($delete_report)) {
	if(not $n->report_delete($delete_report)) {
	    error_msg("Failed to delete report ${delete_report}.");
	    $err = 1;
	}
    }
    else {
	foreach my $report_id (list_reports($n, $delete_report eq 'all'? undef : $delete_report)) {
	    log_msg("Remove report $report_id.");
	    if(not $n->report_delete($report_id)) {
		error_msg("Failed to delete report $report_id.");
		$err = 1;
	    }
	}
    }
    if(not $err) {
	log_msg("Report(s) deleted.");
    }
}
elsif(defined($wait)) {

    log_msg("Wait for $wait.");
    if(is_id($wait)) {
	wait_for_scan($n, $wait);
    }
    else {
	foreach my $uid (@{$n->scan_list_uids()}) {
	    my $name = $n->scan_get_name($uid);
	    if($name eq $wait) {
		wait_for_scan($n, $uid);
	    }
	}
    }
}
else {
    log_msg("Nothing to do.");
    print_help();
}


### helper functions

sub print_help {
    print 
	"\n",
	"usage: $0 [ <options> ] <command> [ <command-options> ]\n\n",
        "  Options: \n",
	"  --server                      - XML-RPC URI of the nessus scan server\n",
	"  --user                        - nessus user\n",
	"  --password                    - password\n",
	"\n",
	"  Commands:\n",
	"  --list-policies               - list available scan policies in nessus\n",
	"  --scan                        - start a new scan\n",
	"    --name <str>                - name of the scan\n",
	"    --policy <str|id>           - policy to use for scanning\n",
	"    --targets <adr> [... <adr>] - targets to scan (e.g. 10.0.1.0/24 10.0.2.0/24)\n",
	"    --file <str>                - specify a file with targets (nmap-xml or a \n",
	"                                  plain text file with a single target per line)\n",
	"    --wait                      - wait for a batch to complete\n",
	"  --list-scans                  - list running scans\n",
	"  --list-reports                - list reports\n",
	"  --download <id|name|all>      - download report\n",
	"  --delete-report <id|all>      - download report\n",
#	"  --pause-scan         - pause a scan\n",
	"  --pause                       - pause all runnings scans\n",
	"  --resume                      - resume all scans\n",
	"  --stop                        - stop all scans\n",
	"  --wait <id>                   - wait for a scan to complete\n",
	"  --batch-size                  - split scans into batches (default size $batch_size)\n",
	"\n\n";
}

sub error_msg {
    my $msg = shift;
    print "\nerror: ", $msg, "\n\n";
    exit(1);
}

sub log_msg {
    my $msg = shift;
    my $level = shift || -1;
    print((' ' x ($level+1)), "+ ", $msg, "\n");
}

sub check_param {
    my ($param, $error_msg) = @_;
    if(not defined $param) {
	error_msg($error_msg);
    }
}

sub hashval_to_str {
    my ($h_ref, $h_key) = @_;
    return exists($h_ref->{$h_key}) && defined($h_ref->{$h_key}) ? $h_ref->{$h_key} : '';
}

sub shorten {
    my ($str, $max_len) = @_;

    if($max_len > 3 ) {
	$max_len -= 3;
    }

    if(length($str) > $max_len) {
	$str = substr($str, 0, $max_len) . '...';
    }
    return $str;
}

sub list_policies {
    my $n = shift;

    log_msg("Get available policies:");
    my $p_list = $n->policy_list_hash();
    foreach my $pi (@$p_list) {
	printf("%3d  %-20s %-10s %-30s %-s\n",
	       hashval_to_str($pi, 'id'),
	       shorten(hashval_to_str($pi, 'owner'), 20),
	       hashval_to_str($pi, 'visibility'),
	       hashval_to_str($pi, 'name'),
	       hashval_to_str($pi, 'comment'));
    }
}


sub list_scans {
    my $n = shift;

    log_msg("Get running scan(s)");
    my $s_list = $n->scan_list_uids();
    log_msg("Found " . ($#$s_list + 1) . " scan(s)");

    if($#$s_list > -1) {
	printf("\n  %-52s  %-18s %s\n", "scan ID", "status", "scan name");
	print "  ", "-" x 80, "\n";
	foreach my $sid (@$s_list) {
	    my $name = $n->scan_get_name($sid);
#	    my $stat = $n->scan_status($sid);
#	    printf("  %s  %-10s %s\n", $sid, $stat, $name);
	    printf("  %s  %-18s %s\n", $sid, status_to_str($n, $sid), $name);
	}
	print "\n";
    }

}

sub list_reports {
    my $n = shift;
    my $filter_name = shift;

    my @report_ids;

    log_msg("Get available reports:");
    my $r_list = $n->report_list_hash();
    log_msg("Found " . ($#$r_list + 1) . " reports(s)");
  
    if($#$r_list > -1) {
	printf("\n  %-52s  %-10s %s\n", "scan ID", "status", "scan name");
	print "  ", "-" x 80, "\n";
	foreach my $ri (@$r_list) {
	    printf("  %s  %-10s %s\n", $ri->{name}, $ri->{status}, $ri->{readableName});

	    if((defined($filter_name) and ($ri->{readableName} eq $filter_name)) or 
	       not defined($filter_name)) {
		push @report_ids, $ri->{name};
	    }
	}
    }
    return @report_ids;
}

sub download_report {
    my ($n, $report_id, $report_file) = @_;

    log_msg("Download report: $report_id");
    
    my $ret = $n->report_file_download($report_id);
    
    if($ret) {
	open(FILE, "> $report_file") or error_msg("Failed to write report file $report_file: $!");
	print FILE $ret;
	close FILE;
	log_msg("Wrote " . length($ret) . " bytes to file " . $report_file . ".");
    }
    else {
	error_msg("Report download failed.");
    }
}


sub batch_scan {
    my ($n, $policy_id, $name, $hosts, $wait, $batch_size) = @_;
    
    my $batch_num = 0;
    while($#$hosts +1 > 0) {
	my @batch;
	my $i = 0;
	while(($#$hosts +1 > 0) and ($#batch + 1 < $batch_size)) {
	    my $t = shift(@$hosts);
	    push @batch, $t;
	}
	my $targets = join(', ', @batch);
        my $scan_id = $n->scan_new($policy_id, $name, $targets);
	

	if($scan_id eq '') {
	    error_msg("Scan failed.");
	}
	else {
	    log_msg("Started a new scan with id " . $scan_id, 1);
	    $batch_num++;
	    if($wait) {
		wait_for_scan($n, $scan_id);
		log_msg("Scan with id " . $scan_id . " finished.", 1);
	    }
	}

    }
    return -1;
}

sub status_to_str {
    my ($n, $sid) = @_;
    my $stat = $n->scan_full_status($sid);
    if(ref($stat)) {
	return sprintf("%s [%d/%d]", $stat->{status}, $stat->{current}, $stat->{total});
    }
    else {
	$stat = $n->scan_status($sid);
	return $stat;
    }
}

sub wait_for_scan {
    my ($n, $scan_id) = @_;
    log_msg("Waiting for scan to finish: $scan_id");
    while(not $n->scan_finished($scan_id)) {
#	log_msg("$scan_id: ". status_to_str($n, $scan_id), 2);
	sleep 15;
    }
}



sub parse_nmap_xml {
    my $file_xml = shift;
    my $np = new Nmap::Parser;
    $np->parsefile($file_xml);
    return $np->get_ips("up");
}

sub parse_targets {
    my $file = shift;
    my @targets;
    my $line;
    open(FILE, "< $file") or error_msg("Can't open file $file: $!");
    while(defined($line = <FILE>)) {
        chomp($line);
        push @targets, $line;
    }
    close FILE;
    return @targets;
}


sub is_id {
    my $id = shift;
    return $id =~ m!^[a-f\d]{8}\-[a-f\d]{4}\-[a-f\d]{4}\-[a-f\d]{4}-[a-f\d]{28}$!;
}
