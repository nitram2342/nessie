
                              _   _       _a_a       
                  _   _     _{.`=`.}_    {/ ''_     
            _    {.`'`.}   {.'  _  '.}  {|  ._oo)    
           {   {/ .-. } {/  .' '.  } {/  |        
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

A command line client for the Nessus scanner based on the CPAN module Net::Nessus::XMLRPC.


Author
----------------

Martin Schobert <martin@weltregierung.de>

Credits
----------------

jgs: for the nessie picture

Installation
----------------

Install the Nessus Scanner.

Install the CPAN module Net::Nessus::XMLRPC:

  $ sudo perl -MCPAN -e shell
  > install Net::Nessus::XMLRPC

Get the ca certificate from your Nessus installation:

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
  cat /opt/nessus/com/nessus/CA/*.pem > ca


Write a configuration file:

 $ cat .nessie
 #user=nessus
 password=secret


Usage
----------------

usage: nessie.pl [ <options> ] <command> [ <command-options> ]

  Options: 
  --server                 - XML-RPC URI of the nessus scan server
  --user                   - nessus user
  --password               - password

  Commands:
  --list-policies          - list available scan policies in nessus
  --scan                   - start a new scan
    --name <str>           - name of the scan
    --policy <str|id>      - policy to use for scanning
    --targets <addrs>      - targets to scan (e.g. '10.0.1.0/24, 10.0.2.0/24')
    --file <str>           - specify a file with targets (nmap-xml or plain text)
  --list-scans             - list running scans
  --list-reports           - list reports
  --download <id|name|all> - download report
  --delete-report <id|all> - download report
  --pause                  - pause all runnings scans
  --resume                 - resume all scans
  --stop                   - stop all scans
  --batch-size             - split scans into batches (default size 16)

Examples
----------------

List policies:

  $ perl nessie.pl --list-policies
  + connected to nessus xmlrpc service
  + get available policies:
   -4  Tenable Policy Di... shared     External Network Scan          
   -3  Tenable Policy Di... shared     Internal Network Scan          
   -2  Tenable Policy Di... shared     Web App Tests                  
   -1  Tenable Policy Di... shared     Prepare for PCI-DSS audits (section 11.2.2) 

Run a scan:

  $ perl nessie.pl --scan --name test --policy -4 --targets 10.0.0.0/24

Run a batched scan:

  $ sudo nmap -v -sn -PS21,22,23,25,53,80,110,135,139,161,389,443,445,993,1025,3389 -oA /tmp/x 10.0.0.0/24
  $ perl nessie.pl --scan -name test --policy fullscan --file /tmp/x.xml

List scans:

  $ perl nessie.pl --list-reports
  + connected to nessus xmlrpc service
  + get available reports:
  + found 1 reports(s)

    scan ID                                               status     scan name
    --------------------------------------------------------------------------------
    c9661473-ceb2-c6d2-71a6-eb7971d628e8b30f0a2e8ebe7663  completed  test

Download reports:

  $ perl nessie.pl --download all
  + connected to nessus xmlrpc service
  + get available reports:
  + found 1 reports(s)

    scan ID                                               status     scan name
    --------------------------------------------------------------------------------
    c9661473-ceb2-c6d2-71a6-eb7971d628e8b30f0a2e8ebe7663  completed  test
  + wrote 1051732 bytes to file c9661473-ceb2-c6d2-71a6-eb7971d628e8b30f0a2e8ebe7663.nessus

Download batch of reports:

  $ perl nessie.pl --download test
  + Connected to nessus xmlrpc service at https://127.0.0.1:8834/.
  + get available reports:
  + found 2 reports(s)

    scan ID                                               status     scan name
    --------------------------------------------------------------------------------
    2a6c57c3-e885-82b9-89f9-cc8dc59e8f6fc320021b33c338ef  completed  test
    61e381f5-8c05-4747-d4ad-a028371d9ef05f77ac5fcc3c5d83  completed  test
  + Download report: 2a6c57c3-e885-82b9-89f9-cc8dc59e8f6fc320021b33c338ef
  + wrote 964381 bytes to file 2a6c57c3-e885-82b9-89f9-cc8dc59e8f6fc320021b33c338ef.nessus
  + Download report: 61e381f5-8c05-4747-d4ad-a028371d9ef05f77ac5fcc3c5d83
  + wrote 671281 bytes to file 61e381f5-8c05-4747-d4ad-a028371d9ef05f77ac5fcc3c5d83.nessus


Inspect report:

  $ perl parse_nessus_reports.pl c9* | less -S

  [...]
  0        10.0.0.xx   631/tcp            ipp? | Nessus SNMP Scanner -- SNMP information is enumerated to learn about other open ports.
  0        10.0.0.xx   515/tcp        printer? | Nessus SNMP Scanner -- SNMP information is enumerated to learn about other open ports.
  0        10.0.0.xx    80/tcp           http? | Nessus SNMP Scanner -- SNMP information is enumerated to learn about other open ports.
  0        10.0.0.xx     0/tcp         general | Nessus Scan Information -- Information about the Nessus scan.
  0        10.0.0.xx     0/tcp         general | Do not scan printers -- The remote host appears to be a fragile device and will not be scanned.
  0        10.0.0.xx   137/udp      netbios-ns | Windows NetBIOS / SMB Remote Host Information Disclosure -- It is possible to obtain [..]
  [...]
