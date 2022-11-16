#!/usr/bin/env python3

# ghsinfosec - 2022

# Interactively work with a subset of the ThreatBlockr API calls
# Currently works with the following calls:
#   - /search/ioc/domain/{domain}
#   - /search/ioc/ip/{ip}
#   - /allow-lists/ip/{uuid}/entries
#   - /block-lists/ip/{uuid}/entries
# others can be added, but this was enough to play with for PoC
# works best on *nix systems - uses 'dig' for DNS lookups


import argparse
import os
import requests
import subprocess


# initialize variables
base_url = 'https://admin.threatblockr.com/api/v4'

# need these headers to make API call
headers = {
        'accept': 'application/json',
        'Authorization': os.environ.get('THREATBLOCKR_API'),
        'Content-Type': 'application/json'}

# endpoints for the API calls that we care about
api_endpoints = {
        'search_ioc_domain': '/search/ioc/domain/',
        'search_ioc_ip': '/search/ioc/ip/',
        'allow_list_ip': '/allow-lists/ip/<UUID-FOR-ALLOW-LIST>/entries',   # get the UUID from the URL of the web console
        'block_list_ip': '/block-lists/ip/<UUID-FOR-BLOCK-LIST>/entries'    # get the UUID from the URL of the web console
        }

# the payload needed for updating allow and block lists - defaults are empty, but can be populated based on arguments
payload_data = [
        {
            'id': '',
            'address': '',
            'maskbits': 0,
            'description': '',
            'expiresDatetime': ''
            }
        ]


# function to get commandline arguments and parse them based on the desired functionality
def get_args():
    parser = argparse.ArgumentParser(prog='threatblockr.py', description='Query or update the ThreatBlockr Appliance through the terminal')
    subparser = parser.add_subparsers(dest='command')

    # query parser to query a domain or IP address
    query_parser = subparser.add_parser('query', help='Query for domain or IP presence')
    query_parser.add_argument('-d', '--domain', dest='domain', help='Domain you want to query')
    query_parser.add_argument('-i', '--ip-address', dest='ip_addr', help='IP address you want to query')

    # mutually exclusive group - either query DNS or threatblockr but not both
    query_group = query_parser.add_mutually_exclusive_group()
    query_group.add_argument('-n', '--nameservers', action='store_true', help='Query nameservers/DNS records for domain')
    query_group.add_argument('-t', '--threatblockr', action='store_true', help='Query ThreatBlockr for domain')

    # allow parser to update the allow list for an IP address
    allow_parser = subparser.add_parser('allow', help='Update the allow list')
    allow_parser.add_argument('-i', '--ip-address', dest='ip_addr', help='IP Address to add to ThreatBlockr list')
    allow_parser.add_argument('-m', '--maskbits', dest='maskbits', type=int, help='CIDR notation maskbits - e.g. 24, 32, etc')
    allow_parser.add_argument('-D', '--description', dest='description', help='Description for the new entry - e.g. "www.example.com"')

    # block parser to update the block list for an IP address
    block_parser = subparser.add_parser('block', help='Update the block list')
    block_parser.add_argument('-i', '--ip-address', dest='ip_addr', help='IP Address to add to ThreatBlockr list')
    block_parser.add_argument('-m', '--maskbits', dest='maskbits', type=int, help='CIDR notation maskbits - e.g. 24, 32, etc')
    block_parser.add_argument('-D', '--description', dest='description', help='Description for the new entry - e.g. "www.example.com"')

    args = parser.parse_args()

    return args


options = get_args()


# function to 'dig' the domain for any IP addresses that it may have
def lookup_dns(domain):

    # ip list to store dns resolutions
    ip_list = list()

    # run the dig command and add the IP's to the ip list
    result = subprocess.check_output(['dig', domain, '+short'])
    ip_list.append(result.decode().strip().split('\n'))
    print(result.decode().strip())

    # ask the user if they want to update a list while they're at it
    add_to_list = input('Do you want to update the ThreatBlockr lists? [y/n]: ')
    # yes, update the list - ask the user if they want to update the allow list or the block list
    if (add_to_list == 'y' or add_to_list == 'yes'):
        allow_or_block = input('Allow list or block list? [allow/block]: ')
        # update allow list
        if allow_or_block.lower() == 'allow':
            for items in ip_list:
                for ip in items:
                    update_allow(ip, 32, domain)
        # update block list
        elif allow_or_block.lower() == 'block':
            for items in ip_list:
                for ip in items:
                    update_block(ip, 32, domain)
        # reject unknown options and quit
        else:
            print('Option unknown. Quitting!')

    # no list updates, just quit
    else:
        print('Done. Quitting!')


# function to search the domain IOC's in ThreatBlockr
def search_domain(domain):
    print(f'==[ Searching ThreatBlockr IOC list for {domain} ]==\n')

    # send a GET request to the API to search for domain presence
    response = requests.get(f'{base_url}{api_endpoints["search_ioc_domain"]}{domain}', headers=headers).text
    print(response)


# function to search the IP IOC's in ThreatBlockr
def search_ip(ip_address):
    print(f'==[ Searching ThreatBlockr IOC list for {ip_address} ]==\n')

    # send a GET request to the API to search for IP address presence
    response = requests.get(f'{base_url}{api_endpoints["search_ioc_ip"]}{ip_address}', headers=headers).text
    print(response)


# function to update the IP allow list 'API Python Script'
def update_allow(ip, maskbits, description):
    payload_data[0]['address'] = ip
    payload_data[0]['maskbits'] = int(maskbits)
    payload_data[0]['description'] = description

    # send a POST request for the allow list IP API call based on arguments provided
    response = requests.post(f'{base_url}{api_endpoints["allow_list_ip"]}', headers=headers, json=payload_data).text
    print(response)


# function to update the IP block list 'API Python Script'
def update_block(ip, maskbits, description):
    payload_data[0]['address'] = ip
    payload_data[0]['maskbits'] = int(maskbits)
    payload_data[0]['description'] = description

    # send a POST request for the block list IP API call based on arguments provided
    response = requests.post(f'{base_url}{api_endpoints["block_list_ip"]}', headers=headers, json=payload_data).text
    print(response)


# main function - checks the subcommands and calls the relevant function based on user provided options
def main():
    if options.command == 'query':
        if options.nameservers:
            lookup_dns(options.domain)
        elif options.threatblockr:
            search_domain(options.domain)
        elif options.ip_addr:
            search_ip(options.ip_addr)
        else:
            pass
    elif options.command == 'allow':
        update_allow(options.ip_addr, options.maskbits, options.description)
    elif options.command == 'block':
        update_block(options.ip_addr, options.maskbits, options.description)
    else:
        pass


if __name__ == '__main__':
    main()
    



