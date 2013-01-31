
                              _   _       _a_a       
                  _   _     _{.`=`.}_    {/ ''\_     
            _    {.`'`.}   {.'  _  '.}  {|  ._oo)    
           { \  {/ .-. \} {/  .' '.  \} {/  |        
    ~jgs^~`~^~`~^~`~^~`~^~^~`^~^~`^~^~^~^~^~^~`^~~`  
 @@@  @@@  @@@@@@@@   @@@@@@   @@@@@@   @@@  @@@@@@@@
 @@@@ @@@  @@@@@@@@  @@@@@@@  @@@@@@@  @@@@  @@@@@@@@
 @@!@!@@@  @@!       !@@      !@@     @@@!!  @@!     
 !@!!@!@!  !@!       !@!      !@!       !@!  !@!     
 @!@ !!@!  @!!!:!    !!@@!!   !!@@!!    @!@  @!!!:!  
 !@!  !!!  !!!!!:     !!@!!!   !!@!!!   !@!  !!!!!:  
 !!:  !!!  !!:            !:!      !:!  !!:  !!:     
 :!:  !:!  :!:           !:!      !:!   :!:  :!:     
  ::   ::   :: ::::  :::: ::  :::: ::   :::   :: ::::
 ::    :   : :: ::   :: : :   :: : :     ::  : :: :: 


About
----------------

Nessie is a command line client for the Nessus scanner based on the CPAN
module Net::Nessus::XMLRPC.

This client is shipped with a set of other useful tools for command line
based security tests. These additional tools are:

ping_sweep.sh           -- An nmap based host discovery tool.
hosts_up.pl             -- Parse an nmap file and extract running hosts.
                           It is possible to filter by active ports.
parse_nessus_reports.pl -- Parse a set of Nessus reports and display
                           the results in a table.


Installation
----------------

Install the Nessus scanner module.

  Install the CPAN module Net::Nessus::XMLRPC. Please use the
  version from github, which has additional features and bugfixes.
  It should not be a problem, If you have already installed another
  Net::Nessus::XMLRPC module globally, because 'make install' will
  place the new module in your home directory.

  $ git clone git://github.com/nitram2342/Nessus-xmlrpc-perl.git
  $ cd Nessus-xmlrpc-perl
  $ perl Makefile.pl
  $ make install


Get the CA certificate from your Nessus installation:

  $ sh get_cert.sh
  [...]
  -----BEGIN CERTIFICATE-----
  xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  -----END CERTIFICATE-----

  Copy the certificate into file 'ca'.

OR:

  Copy the certificates locally:
  cat /opt/Nessus/com/Nessus/CA/*.pem > ca


Write a configuration file:

 $ cat .nessie
 #user=Nessus
 password=secret

 Place the config file in either the same directory as the client
 or in your home directory. If you do not have a configuration file,
 you need to specify the Nessus credentials via command line parameter.


Usage
----------------

usage: nessie.pl [ <options> ] <command> [ <command-options> ]

  Options: 
  --server                      - XML-RPC URI of the nessus scan server
  --user                        - nessus user
  --password                    - password

  Commands:
  --list-policies               - list available scan policies in nessus
  --scan                        - start a new scan
    --name <str>                - name of the scan
    --policy <str|id>           - policy to use for scanning
    --targets <adr> [... <adr>] - targets to scan (e.g. 10.0.1.0/24 10.0.2.0/24)
    --file <str>                - specify a file with targets (nmap-xml or a 
                                  plain text file with a single target per line)
    --wait                      - wait for a batch to complete
  --list-scans                  - list running scans
  --list-reports                - list reports
  --download <id|name|all>      - download report
  --delete-report <id|all>      - download report
  --pause                       - pause all runnings scans
  --resume                      - resume all scans
  --stop                        - stop all scans
  --wait <id>                   - wait for a scan to complete
  --batch-size                  - split scans into batches (default size 16)



Examples
----------------

List policies:

  $ perl nessie.pl --list-policies
  + connected to Nessus xmlrpc service
  + get available policies:
   -4  Tenable Policy Di... shared     External Network Scan          
   -3  Tenable Policy Di... shared     Internal Network Scan          
   -2  Tenable Policy Di... shared     Web App Tests                  
   -1  Tenable Policy Di... shared     Prepare for PCI-DSS audits (section 11.2.2) 

Run a scan:

  $ perl nessie.pl --scan --name test --policy -4 --targets 10.0.0.0/24

Run a batched scan:

  Run host discovery, which writes an nmap file.
  $ sudo ping_sweep.sh 10.0.0.0/24

  Run the scan:
  $ perl nessie.pl --scan -name test --policy fullscan --file pingsweep_<date>.xml

List scans:

  $ perl nessie.pl --list-reports
  + connected to Nessus xmlrpc service
  + get available reports:
  + found 1 reports(s)

    scan ID                                               status     scan name
    --------------------------------------------------------------------------------
    c9661473-ceb2-c6d2-71a6-eb7971d628e8b30f0a2e8ebe7663  completed  test

Download reports:

  $ perl nessie.pl --download all
  + connected to Nessus xmlrpc service
  + get available reports:
  + found 1 reports(s)

    scan ID                                               status     scan name
    --------------------------------------------------------------------------------
    c9661473-ceb2-c6d2-71a6-eb7971d628e8b30f0a2e8ebe7663  completed  test
  + wrote 1051732 bytes to file c9661473-ceb2-c6d2-71a6-eb7971d628e8b30f0a2e8ebe7663.Nessus

Download batch of reports:

  $ perl nessie.pl --download test
  + Connected to Nessus xmlrpc service at https://127.0.0.1:8834/.
  + get available reports:
  + found 2 reports(s)

    scan ID                                               status     scan name
    --------------------------------------------------------------------------------
    2a6c57c3-e885-82b9-89f9-cc8dc59e8f6fc320021b33c338ef  completed  test
    61e381f5-8c05-4747-d4ad-a028371d9ef05f77ac5fcc3c5d83  completed  test
  + Download report: 2a6c57c3-e885-82b9-89f9-cc8dc59e8f6fc320021b33c338ef
  + wrote 964381 bytes to file 2a6c57c3-e885-82b9-89f9-cc8dc59e8f6fc320021b33c338ef.Nessus
  + Download report: 61e381f5-8c05-4747-d4ad-a028371d9ef05f77ac5fcc3c5d83
  + wrote 671281 bytes to file 61e381f5-8c05-4747-d4ad-a028371d9ef05f77ac5fcc3c5d83.Nessus


Inspect report:

  $ perl parse_nessus_reports.pl --files *.nessus --sort severity| less -S

  [...]
  0  10.0.0.xx  631/tcp       ipp? | Nessus SNMP Scanner -- SNMP information [..]
  0  10.0.0.xx  515/tcp   printer? | Nessus SNMP Scanner -- SNMP information [..]
  0  10.0.0.xx   80/tcp      http? | Nessus SNMP Scanner -- SNMP information [..]
  0  10.0.0.xx    0/tcp    general | Nessus Scan Information -- Information  [..]
  0  10.0.0.xx    0/tcp    general | Do not scan printers -- The remote host [..]
  0  10.0.0.xx  137/udp netbios-ns | Windows NetBIOS / SMB Remote Host Infor [..]
  [...]

Credits
----------------

jgs: for the nessie picture

Author
----------------

Martin Schobert <martin@weltregierung.de>
