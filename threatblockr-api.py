#!/usr/bin/env python3

# ghsinfosec - 2022

# Interactively work with a subset of the ThreatBlockr API calls
# Currently works with the following calls:
#   - /search/ioc/domain/{domain}
#   - /allow-lists/ip/{uuid}/entries
#   - /block-lists/ip/{uuid}/entries
# others can be added, but this was enough to play with for PoC
# works best on *nix systems - uses 'dig' for DNS lookups


import argparse
import globals
import query
import update
import report


globals.init()


# function to get commandline arguments and parse them based on the desired functionality
def get_args():
    parser = argparse.ArgumentParser(prog='threatblockr-api.py', description='Query or update the ThreatBlockr Appliance through the terminal')
    subparser = parser.add_subparsers(dest='command')

    query.setup_args(subparser)
    update.setup_args(subparser)
    report.setup_args(subparser)

    args = parser.parse_args()

    return args


# main function - checks the subcommands and calls the relevant function based on user provided options
def main():
    options = get_args()
    
    command_map = {
            "query": query.run,
            "update": update.run,
            "report": report.run,
            }
    
    command_map[options.command](options)


if __name__ == '__main__':
    main()
    
