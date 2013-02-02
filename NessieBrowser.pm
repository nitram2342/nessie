package NessieBrowser;

#use strict;
use Curses::UI;
use Text::Table;
use Data::Dumper;
use Data::Diver qw/Dive/;

sub new {

    my $class = shift;
    my $report_items = shift; 

    my $self = { vulnerabilities => _create_vulnerabilities($report_items),
		 hosts => _create_hosts($report_items),
		 services => _create_services($report_items)};

    #
    # setup GUI
    #
    $self->{cui} = new Curses::UI(-clear_on_exit => 0,
				  -color_support => 1);

    #
    # Setup main window
    #
    $self->{w_vuln} = $self->{cui}->add('w_vuln',
				       'Window',
				       -border => 1,
				       -bfg => "red",
				       -title => "Nessie Browser :: Vulnerabilities");

    my $max_height = $self->{w_vuln}->height();
    my $max_width = $self->{w_vuln}->width();

    $self->{w_vuln_lbox} = $self->{w_vuln}->add('List',
						'Listbox',
						-fg => "white",
						-height => int ($max_height / 2));
    
    $self->{w_vuln_tbox} = $self->{w_vuln}->add('textbox',
						'TextViewer',
						-fg => "white",
						-border => 1,
						-y => ($max_height / 2),
						-height => int ($max_height / 2));


    $self->{w_vuln_lbox}->set_binding( sub { $self->{w_vuln_tbox}->focus() },	"\t");

#    $self->{lbox}->set_binding( sub { my $id = $self->{w_vuln_lbox}->get_active_id();
#				      my $res = $self->{resource}->{$id};
#				      if($res) {
#					  my $yes = $self->{cui}->question(-title   => 'Open',
#									   -question => 'Should I run the folloing command?',
#									   -answer => $res,
#									   -buttons => ['yes','no'],
#									   -values  => [1, 0]);
#					  if($yes) {
#					      $self->open_resource($res);
#					  }
#				      }
#				}, "o");

#    $self->{cui}->status("Parsing nessus reports ...");

    $self->{w_vuln_lbox}->onSelectionChange( sub { my $id = $self->{w_vuln_lbox}->get_active_id();
						   $self->show_vulnerability_details($id); } );


    #
    # Window: Hosts
    #
    $self->{w_hosts} = $self->{cui}->add('w_hosts',
					 'Window',
					 -border => 1,
					 -bfg => "red",
					 -title => "Nessie Browser :: Hosts");

    $self->{w_hosts_lbox} = $self->{w_hosts}->add('List',
						  'Listbox',
						  -fg => "white",
						  -height => $max_height);

    #
    # Window: Services
    #
    $self->{w_services} = $self->{cui}->add('w_services',
					    'Window',
					    -border => 1,
					    -bfg => "red",
					    -title => "Nessie Browser :: Services");

    $self->{w_services_lbox} = $self->{w_services}->add('List',
							'Listbox',
							-fg => "white",
							-height => $max_height);


    #
    # Key bindings
    #

    $self->{cui}->set_binding ( sub { exit 0 },	"\cQ", "\cC");

    $self->{cui}->set_binding ( sub { $self->show_vulnerabilities() }, "v");
    $self->{cui}->set_binding ( sub { $self->show_hosts() }, "h");
    $self->{cui}->set_binding ( sub { $self->show_services() }, "s");


    bless $self, $class;
    return $self;
}

sub _create_vulnerabilities {
 
    my $results = shift;

    my @x1 = sort{ ($b->{severity} <=> $a->{severity}) || 
		       ($b->{pluginName} cmp $a->{pluginName}) ||
		       ($a->{host} cmp $b->{host}) ||
		       ($a->{port} <=> $b->{port}) ||
		       ($a->{protocol} cmp $b->{protocol}) } @$results;

    my $tb = Text::Table->new(qw(Sv. Host Port Service Xplt Plugin));

    foreach my $ri (@x1) {
    
	$tb->add($ri->{severity},
		 $ri->{_host},
		 ($ri->{port} ne '0') ? ( $ri->{port} . ' ' . $ri->{protocol}) : '',
		 substr($ri->{svc_name}, 0, 10),
		 (lc($ri->{exploit_available}) eq 'true' ? 'X' : ''),
		 $ri->{pluginName});
    }

    my @t = $tb->table();
    return { table => \@t,
	     nessus => $results};
}

sub show_vulnerabilities {
    my ($self) = @_;

#    $self->{w_vuln}->focus();
    $self->{w_vuln_lbox}->values($self->{vulnerabilities}->{table});
    $self->{w_vuln_lbox}->focus();
}


sub show_vulnerability_details {
    my ($self, $id) = @_;

    my $text = '';
    if($id > 0) {
	my $ri = $self->{vulnerabilities}->{nessus}->[$id - 1];

	$text = 
	    $ri->{synopsis} . "\n" . 
	    "-------------------------------------------------\n".
	    $ri->{description} . "\n" . 
	    "-------------------------------------------------\n".
	    $ri->{plugin_output};
    }
    
    $self->{w_vuln_tbox}->text($text); 
}


sub _shorten_os {
    my $str = shift;
    $str =~ s!Microsoft!MS!;
    $str =~ s!Windows!Win!;
    $str =~ s!Standard!Std!;
    $str =~ s!Server!Srv!;
    $str =~ s!Service Pack !SP!;
    $str =~ s!Linux Kernel!Linux!;
    return $str;
}

sub _create_hosts {
    my $report_items = shift;

    my @x2 = sort { ($a->{_host} cmp $b->{_host})  ||
			($a->{protocol} cmp $b->{protocol}) ||
			($a->{port} <=> $b->{port})} @$report_items;

    my $tb = Text::Table->new(qw(Host MAC NetBIOS OS));

    my %seen;

    foreach my $ri (@x2) {
    
	my $host = $ri->{_host};

	if(not exists($seen{$host})) {
	    $seen{$host} = 1;

	    my $h = $ri->{_ReportHost};
	    my $m = Dive($h, qw(HostProperties tag mac-address  content));
	    my $n = Dive($h, qw(HostProperties tag netbios-name content));
	    my $o = Dive($h, qw(HostProperties tag operating-system content));
	    
	    $tb->add($host, $m, $n, _shorten_os($o));
	}
    }

    my @t = $tb->table();
#    print Dumper(\@t);
    return { table => \@t,
	     nessus => $results};
}

sub show_hosts {
    my ($self, $id) = @_;
    $self->{w_hosts_lbox}->values($self->{hosts}->{table});
    $self->{w_hosts}->focus();
}


sub _create_services {
   
    my $results = shift;
    my $tb = Text::Table->new(qw( Host Proto Port Service ));

    my @x1 = grep {$_->{pluginFamily} eq 'Port scanners' } @$results;

    my @x2 = sort { ($a->{_host} cmp $b->{_host})  ||
			($a->{protocol} cmp $b->{protocol}) ||
			($a->{port} <=> $b->{port})} @x1;

    foreach my $ri (@x2) {
    
	$tb->add($ri->{_host},
		 $ri->{protocol},
		 $ri->{port},
		 $ri->{svc_name});
    }

    my @t = $tb->table();
    return { table => \@t,
	     nessus => $results};
}

sub show_services {
    my ($self, $id) = @_;
    $self->{w_services_lbox}->values($self->{services}->{table});
    $self->{w_services}->focus();
}


sub run {
    my $self = shift;
    $self->show_vulnerabilities();
#    $self->show_hosts();
#    $self->show_services();
    $self->{cui}->mainloop();
}

1;
