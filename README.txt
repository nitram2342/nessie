About
----------------

A command line client for the Nessus scanner based on the CPAN module Net::Nessus::XMLRPC.


Author
----------------

Martin Schobert <martin@weltregierung.de>

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
    --file <str>           - specify a file with targets
  --list-scans             - list running scans
  --list-reports           - list reports
  --download <id>          - download report
  --delete-report <id|all> - download report
  --pause                  - pause all runnings scans
  --resume                 - resume all scans
  --stop                   - stop all scans
  --batch-size             - split scans into batches (default size 20)


Examples
----------------

Set the pass:

   PASS=secret

List policies:

  $ perl nessie.pl --password $PASS --list-policies
  + connected to nessus xmlrpc service established and authenticated
  + get available policies:
   -4  Tenable Policy Di... shared     External Network Scan          
   -3  Tenable Policy Di... shared     Internal Network Scan          
   -2  Tenable Policy Di... shared     Web App Tests                  
   -1  Tenable Policy Di... shared     Prepare for PCI-DSS audits (section 11.2.2) 

Run a scan:

  $ perl nessie.pl --password $PASS --scan --name test --policy -4 --targets 10.0.0.0/24


List scans:

  $ perl nessie.pl --password $PASS --list-reports
  + connected to nessus xmlrpc service established and authenticated
  + get available reports:
  + found 1 reports(s)

    scan ID                                               status     scan name
    --------------------------------------------------------------------------------
    c9661473-ceb2-c6d2-71a6-eb7971d628e8b30f0a2e8ebe7663  completed  test

Download reports:

  $ perl nessie.pl --password $PASS --download all
  + connected to nessus xmlrpc service established and authenticated
  + get available reports:
  + found 1 reports(s)

    scan ID                                               status     scan name
    --------------------------------------------------------------------------------
    c9661473-ceb2-c6d2-71a6-eb7971d628e8b30f0a2e8ebe7663  completed  test
  + wrote 1051732 bytes to file c9661473-ceb2-c6d2-71a6-eb7971d628e8b30f0a2e8ebe7663.nessus

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
