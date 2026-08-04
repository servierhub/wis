#!/usr/bin/env python
""" wis - Bulk WHOIS search
License: 3-clause BSD (see https://opensource.org/licenses/BSD-3-Clause)
Author: Hubert Tournier
"""

import getopt
import gzip
import ipaddress
import logging
import os
import re
import sys

import libpnu

# Version string used by the what(1) and ident(1) commands:
ID = "@(#) $Id: wis - Bulk WHOIS search v1.0.2 (August 4, 2026) by Hubert Tournier $"

# Default parameters. Can be overcome by environment variables, then command line options
parameters = {
    "Case sensitive": False,
    "Dirname": "",
    "Excluded filename": "",
    "Excluded list": [],
    "Filename": "",
    "Included list": [],
    "Show first line only": False,
    "Show inetnum": False,
    "Show inet6num": False,
    "Show expanded ranges": False,
    "Show summary": False,
    "Show summary only": False,
    "Summary": {},
    "Field separator": '|'
}


################################################################################
def _display_help():
    """Displays usage and help"""
    print("usage: wis [--debug] [--help|-?] [--version]", file=sys.stderr)
    print("       [-1|--first] [-c|--case] [-d|--dirname DIR]", file=sys.stderr)
    print("       [-e|--exclude EXCLUDE_FILE] [-f|--filename FILE]", file=sys.stderr)
    print("       [-i|--inet4] [-I|--inet6] [-r|--range]", file=sys.stderr)
    print("       [-s|--summary] [-S|--summaryonly]", file=sys.stderr)
    print("       [--] QUERY [...]", file=sys.stderr)
    print(
        "  ------------------  --------------------------------------------------",
        file=sys.stderr
    )
    print("  -1|--first          Show only the first line of each matching record", file=sys.stderr)
    print("  -c|--case           Make searches case sensitive", file=sys.stderr)
    print("  -d|--dirname DIR    Use databases from the DIR directory name", file=sys.stderr)
    print("  -e|--exclude FILE   Exclude words from the FILE file name", file=sys.stderr)
    print("  -f|--filename FILE  Use database from the FILE file name", file=sys.stderr)
    print("  -i|--inet4          Show only reformatted inetnum records", file=sys.stderr)
    print("  -I|--inet6          Show only reformatted inet6num records", file=sys.stderr)
    print("  -r|--range          Show expanded inet(6)num ranges", file=sys.stderr)
    print("  -s|--summary        Show a summary of the type of matching records", file=sys.stderr)
    print("  -S|--summaryonly    Show only a summary of the type of matching records",
        file=sys.stderr
    )
    print("  --debug             Enable debug mode", file=sys.stderr)
    print("  --help|-?           Print usage and this help message and exit", file=sys.stderr)
    print("  --version           Print version and exit", file=sys.stderr)
    print("  --                  Options processing terminator", file=sys.stderr)
    print(file=sys.stderr)


################################################################################
def _process_environment_variables():
    """Process environment variables"""
    if "WIS_DEBUG" in os.environ:
        logging.disable(logging.NOTSET)


################################################################################
def _process_command_line():
    """Process command line options"""
    # pylint: disable=C0103
    global parameters
    # pylint: enable=C0103

    # option letters followed by : expect an argument
    # same for option strings followed by =
    character_options = "1cd:e:f:iIrsS?"
    string_options = [
        "case",
        "debug",
        "dirname=",
        "exclude=",
        "filename=",
        "first",
        "help",
        "inet4",
        "inet6",
        "range",
        "summary",
        "summaryonly",
        "version",
    ]

    try:
        options, remaining_arguments = getopt.getopt(
            sys.argv[1:], character_options, string_options
        )
    except getopt.GetoptError as error:
        logging.critical("Syntax error: %s", error)
        _display_help()
        sys.exit(1)

    for option, argument in options:

        if option == "--debug":
            logging.disable(logging.NOTSET)

        elif option in ("--case", "-c"):
            parameters["Case sensitive"] = True

        elif option in ("--dirname", "-d"):
            parameters["Dirname"] = argument

        elif option in ("--exclude", "-e"):
            parameters["Excluded filename"] = argument

        elif option in ("--filename", "-f"):
            parameters["Filename"] = argument

        elif option in ("--first", "-1"):
            parameters["Show first line only"] = True
            parameters["Show inetnum"] = False
            parameters["Show inet6num"] = False

        elif option in ("--help", "-?"):
            _display_help()
            sys.exit(0)

        elif option in ("--inet4", "-i"):
            parameters["Show inetnum"] = True
            parameters["Show first line only"] = False

        elif option in ("--inet6", "-I"):
            parameters["Show inet6num"] = True
            parameters["Show first line only"] = False

        elif option in ("--range", "-r"):
            parameters["Show expanded ranges"] = True

        elif option in ("--summary", "-s"):
            parameters["Show summary"] = True

        elif option in ("--summaryonly", "-S"):
            parameters["Show summary only"] = True

        elif option == "--version":
            print(ID.replace("@(" + "#)" + " $" + "Id" + ": ", "").replace(" $", ""))
            sys.exit(0)

    return remaining_arguments


################################################################################
def process_inetnum_block(block):
    """Process an inetnum text block and eventually print it"""
    details = {"start": "", "stop": "", "netname": "", "descr": "", "org": "", "country": ""}
    for line in block:
        if line.startswith("inetnum:"):
            inetnum = re.sub(r"^inetnum:[ 	]*", "", line)
            inet_start = re.sub(r" - .*$", "", inetnum)
            inet_stop = re.sub(r"^[.0-9]* - ", "", inetnum)
            details["start"] = inet_start
            details["stop"] = inet_stop
        elif line.startswith("netname:"):
            netname = re.sub(r"^netname:[ 	]*", "", line)
            if details["netname"]:
                details["netname"] += ", " + netname
            else:
                details["netname"] = netname
        elif line.startswith("descr:"):
            descr = re.sub(r"^descr:[ 	]*", "", line)
            if details["descr"]:
                details["descr"] += ", " + descr
            else:
                details["descr"] = descr
        elif line.startswith("org:"):
            org = re.sub(r"^org:[ 	]*", "", line)
            if details["org"]:
                details["org"] += ", " + org
            else:
                details["org"] = org
        elif line.startswith("country:"):
            country = re.sub(r"^country:[ 	]*", "", line)
            if details["country"]:
                details["country"] += ", " + country
            else:
                details["country"] = country

    if parameters["Show expanded ranges"]:
        start_ip = ipaddress.IPv4Address(details["start"])
        end_ip = ipaddress.IPv4Address(details["stop"])
        networks = list(ipaddress.summarize_address_range(start_ip, end_ip))
        for network in networks:
            for host in network:
                last_host = network[-1]
                if host == network[0]:
                    address_type = "Network"
                elif host == last_host:
                    address_type = "Broadcast"
                else:
                    address_type = "IP address"

                fs = parameters["Field separator"]
                print(
                    f'{str(host)}{fs}{address_type}{fs}{str(network)}{fs}{details["netname"]}{fs}'
                    + f'{details["descr"]}{fs}{details["org"]}{fs}{details["country"]}'
                )

    else:
        fs = parameters["Field separator"]
        print(
            f'{details["start"]}{fs}{details["stop"]}{fs}{details["netname"]}{fs}{details["descr"]}'
            + f'{fs}{details["org"]}{fs}{details["country"]}'
        )

################################################################################
def process_inet6num_block(block):
    """Process an inet6num text block and eventually print it"""
    details = {"start": "", "stop": "", "netname": "", "descr": "", "org": "", "country": ""}
    for line in block:
        if line.startswith("inet6num:"):
            inet6num = re.sub(r"^inet6num:[ 	]*", "", line)
            inet_start = re.sub(r" - .*$", "", inet6num)
            inet_stop = re.sub(r"^.* - ", "", inet6num)
            details["start"] = inet_start
            details["stop"] = inet_stop
        elif line.startswith("netname:"):
            netname = re.sub(r"^netname:[ 	]*", "", line)
            if details["netname"]:
                details["netname"] += ", " + netname
            else:
                details["netname"] = netname
        elif line.startswith("descr:"):
            descr = re.sub(r"^descr:[ 	]*", "", line)
            if details["descr"]:
                details["descr"] += ", " + descr
            else:
                details["descr"] = descr
        elif line.startswith("org:"):
            org = re.sub(r"^org:[ 	]*", "", line)
            if details["org"]:
                details["org"] += ", " + org
            else:
                details["org"] = org
        elif line.startswith("country:"):
            country = re.sub(r"^country:[ 	]*", "", line)
            if details["country"]:
                details["country"] += ", " + country
            else:
                details["country"] = country

    if parameters["Show expanded ranges"]:
        start_ip = ipaddress.IPv6Address(details["start"])
        end_ip = ipaddress.IPv6Address(details["stop"])
        networks = list(ipaddress.summarize_address_range(start_ip, end_ip))
        for network in networks:
            for host in network:
                last_host = network[-1]
                if host == network[0]:
                    address_type = "Network"
                elif host == last_host:
                    address_type = "Broadcast"
                else:
                    address_type = "IP address"

                fs = parameters["Field separator"]
                print(
                    f'{str(host)}{fs}{address_type}{fs}{str(network)}{fs}{details["netname"]}{fs}'
                    + f'{details["descr"]}{fs}{details["org"]}{fs}{details["country"]}'
                )

    else:
        fs = parameters["Field separator"]
        print(
            f'{details["start"]}{fs}{details["stop"]}{fs}{details["netname"]}{fs}{details["descr"]}'
            + f'{fs}{details["org"]}{fs}{details["country"]}'
        )

################################################################################
def process_block(block):
    """Process a text block and eventually print it"""
    if parameters["Included list"]:
        display = False
    else:
        display = True

    if parameters["Case sensitive"]:
        for word in parameters["Included list"]:
            if any(word in element for element in block):
                display = True
    else:
        for word in parameters["Included list"]:
            if any(word.lower() in element.lower() for element in block):
                display = True

    # Word exclusion list is case insensitive
    for word in parameters["Excluded list"]:
        if any(word in element.lower() for element in block):
            display = False

    if display:
        if not parameters["Show summary only"]:
            if parameters["Show first line only"]:
                print(block[0])
            elif parameters["Show inetnum"] or parameters["Show inet6num"]:
                if block[0].startswith("inetnum:") and parameters["Show inetnum"]:
                    process_inetnum_block(block)

                if block[0].startswith("inet6num:") and parameters["Show inet6num"]:
                    process_inet6num_block(block)
            else:
                for line in block:
                    print(line)
                print()

        if parameters["Show summary"] or parameters["Show summary only"]:
            record_type = re.sub(r":.*", "", block[0])
            if not record_type.startswith("#"):
                if record_type in parameters["Summary"]:
                    parameters["Summary"][record_type] += 1
                else:
                    parameters["Summary"][record_type] = 1


################################################################################
def parse_blocks(file):
    """Parse text blocks delimited by a blank line in a file descriptor"""
    block = []
    line = file.readline()
    while line:
        if line.strip() == "":
            if block:
                process_block(block)
                block = []
        else:
            block.append(line.strip())

        line = file.readline()

    if block:
        process_block(block)


################################################################################
def process_file(filename):
    """Process a plain text or gzipped file"""
    if filename.endswith(".gz"):
        file = gzip.open(filename, "rt", encoding="utf-8", errors="ignore")
    else:
        file = open(filename, "rt", encoding="utf-8", errors="ignore")

    parse_blocks(file)

    file.close()


################################################################################
def main():
    """The program's main entry point"""
    exit_status = 0
    program_name = os.path.basename(sys.argv[0])
    libpnu.initialize_debugging(program_name)
    libpnu.handle_interrupt_signals(libpnu.interrupt_handler_function)
    _process_environment_variables()

    # Words we'll be searching for, if any:
    parameters["Included list"] = _process_command_line()

    # Words we won't want in the results:
    if parameters["Excluded filename"]:
        if os.path.isfile(parameters["Excluded filename"]):
            with open(parameters["Excluded filename"], "rt", encoding="utf-8", errors="ignore") \
            as file:
                line = file.readline()
                while line:
                    parameters["Excluded list"].append(line.lower().strip())
                    line = file.readline()
        else:
            logging.critical(
                "Parameter error: '%s' is not an existing or readable file name",
                parameters["Excluded filename"]
            )
            exit_status = 1

    # Process a single database
    if parameters["Filename"]:
        if os.path.isfile(parameters["Filename"]):
            process_file(parameters["Filename"])
        else:
            logging.critical(
                "Parameter error: '%s' is not an existing or readable file name",
                parameters["Filename"]
            )
            exit_status = 1

    # Process multiple databases
    if parameters["Dirname"]:
        if os.path.isdir(parameters["Dirname"]):
            for item_name in os.listdir(parameters["Dirname"]):
                if os.path.isfile(parameters["Dirname"] + os.sep + item_name) \
                and ".db" in item_name:
                    process_file(parameters["Dirname"] + os.sep + item_name)
        else:
            logging.critical(
                "Parameter error: '%s' is not an existing or readable directory name",
                parameters["Dirname"]
            )
            exit_status = 1

    # Print summary
    if parameters["Filename"] or parameters["Dirname"]:
        if parameters["Show summary"] or parameters["Show summary only"]:
            print()
            print("Matching records summary:")
            for key, value in parameters["Summary"].items():
                print(f"    {key}: {value}")
    else:
        logging.error("You didn't provide any database to use!")
        exit_status = 1

    sys.exit(exit_status)


if __name__ == "__main__":
    main()
