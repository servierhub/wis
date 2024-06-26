# Installation
Depending on if you want only this tool, the full set of PNU tools, or PNU plus a selection of additional third-parties tools, use one of these commands:

pip install [pnu-wis](https://pypi.org/project/pnu-wis/)
<br>
pip install [PNU](https://pypi.org/project/PNU/)
<br>
pip install [pytnix](https://pypi.org/project/pytnix/)

# WIS(1)

## NAME
wis - Bulk WHOIS Search

[![Servier Inspired](https://raw.githubusercontent.com/servierhub/.github/main/badges/inspired.svg)](https://github.com/ServierHub/)

## SYNOPSIS
**wis**    
\[-1|--first\]
\[-c|--case\]
\[-d|--dirname DIR\]
\[-e|--exclude FILE\]
\[-f|--filename FILE\]
\[-i|--inet4\]
\[-I|--inet6\]
\[-r|--range\]
\[-s|--summary\]
\[-S|--summaryonly\]
\[--debug\]
\[--help|-?\]
\[--version\]
\[--\]
KEYWORD
\[...\]

## DESCRIPTION
The **wis** utility searches for keyword(s) within bulk WHOIS database(s).

Beside saving multiple WHOIS queries, using pre-downloaded bulk WHOIS databases enables to do plain text searches on all the WHOIS records.

You can either select one specific database (in plain text or gzipped format) using the *-f|--filename FILE* option, or/and a directory containing all your databases using the *-d|--dirname DIR* option.

Use the *-c|--case* option to make your searches case sensitive.

Use the *-e|--exclude FILE* option to provide a one-excluded-case-insensitive-keyword-per-line file to filter out matching records.

You'll then obtain a list of records matching at least one of your keywords, and not matching any of the excluded keywords.

If you use the *-1|--first* option, you'll instead only obtain the first line of each matching record.

If you use the *-i|--inet4* and/or *-I|--inet6* option(s), you'll instead obtain only matching inetnum or inet6num records reformatted as a pipe-separated-values of networks:
```
starting IP address|ending IP Address|netname|descr|org|country
```
If you add the *-r|--range* option to the last ones, you'll instead obtain only matching inetnum or inet6num records reformatted as a pipe-separated-values of hosts:
```
IP address|type|subnet|netname|descr|org|country
```
Where type is either "Network" for the first address in a subnet, "Broadcast" for the last address in a subnet or "IP address" for the rest.

If you use the *-s|--summary* option, you'll get a summary of the record types found (from the first line of each matching record, before the colon).

If you use the *-S|--summaryonly* option you'll only get that.

### OPTIONS
Options | Use
------- | ---
-1\|--first|Show only the first line of each matching record
-c\|--case|Make searches case sensitive
-d\|--dirname DIR|Use databases from the DIR directory name
-e\|--exclude FILE|Exclude words from the FILE file name
-f\|--filename FILE|Use database from the FILE file name
-i\|--inet4|Show only reformatted inetnum records
-I\|--inet6|Show only reformatted inet6num records
-r\|--range|Show expanded inet(6)num ranges
-s\|--summary|Show a summary of the type of matching records
-S\|--summaryonly|Show only a summary of the type of matching records
--debug|Enable debug mode
--help\|-?|Print usage and a short help message and exit
--version|Print version and exit
--|Options processing terminator

## ENVIRONMENT
The WIS_DEBUG environment variable can also be set to any value to enable debug mode.

## FILES
The **wis** utility uses bulk WHOIS databases downloaded from the main [Regional Internet Registries (RIR)](https://www.iana.org/numbers) and [National Internet Registries (NIR)](https://en.wikipedia.org/wiki/National_Internet_registry).

The provided "fetch-db-WHOIS.sh" script can be used for doing this.

You can also use bulk RR (Routing Registries) databases, that you can download with the provided "fetch-db-RR.sh" script.

Be sure to read the databases respective terms of use before!

## EXIT STATUS
The **wis** utility exits 0 on success, and >0 if an error occurs.

## EXAMPLES
Assuming that you have installed the available bulk WHOIS databases (in gzipped format) in a directory named "db", and that you made a one-excluded-keyword-per-line file named "excluded.txt", use the following commands:

* to extract full WHOIS information about matching blocks:
```Shell
wis -d db -e excluded.txt keyword1 keyword2 keyword3
```

* to extract only the first line of WHOIS information about matching blocks:
```Shell
wis -d db -e excluded.txt -1 keyword1 keyword2 keyword3
```

* to extract an IPv4 network summary about matching blocks:
```Shell
wis -d db -e excluded.txt -i keyword1 keyword2 keyword3
```

* to extract an IPv4 host summary about matching blocks:
```Shell
wis -d db -e excluded.txt -ir keyword1 keyword2 keyword3
```

* to analyze a database record types:
```Shell
wis -f database_name.db.gz -S 
```

## SEE ALSO
[whois(1)](https://www.freebsd.org/cgi/man.cgi?query=whois)

## STANDARDS
The **wis** utility is not a standard UNIX command.

This implementation tries to follow the [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide for [Python](https://www.python.org/) code.

## PORTABILITY
Tested OK under Windows.

## HISTORY
This implementation was made for the [PNU project](https://github.com/HubTou/PNU).

Its first use case was to identify all my company's IP addresses ranges through the world, helping to secure our networks and identify shadow IT...

The initial name of the command was "AS Search", but the resulting short form seemed problematic... So I went for a **wis**er name :smiley:

## LICENSE
It is available under the [3-clause BSD license](https://opensource.org/licenses/BSD-3-Clause).

## AUTHORS
[Hubert Tournier](https://github.com/HubTou)

## CAVEAT
Only the AFRINIC, RIPE, APNIC, APNIC/JPNIC, APNIC/TWNIC and APNIC/KISA databases have useful *domain*, *inetnum*, *inet6num* and *organisation* information.

LACNIC does not provide useful *inetnum* and *inet6num* information.

ARIN, APNIC/IDNIC, APNIC/CNNIC, APNIC/VNNIC and APNIC/IRINN do not provide *domain*, *inetnum*, *inet6num* and *organisation* information at all.

However you can find *route* information from all of them, which can then be used with regular WHOIS queries.

