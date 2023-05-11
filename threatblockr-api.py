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
import json
import os
import requests
import subprocess
from time import sleep


# initialize variables
base_url = 'https://admin.threatblockr.com/api/v5'
edge_uuid = '<YOUR-EDGE-INSTANCE-UUID>'

# need these headers to make API call
headers = {
        'accept': 'application/json',
        'Authorization': os.environ.get('THREATBLOCKR_API'),
        'Content-Type': 'application/json'}

# endpoints for the API calls that we care about
api_endpoints = {
        'search_ioc_domain': '/search/ioc/domain/',
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

# TODO:
'''
1. build out report options for different report types
2. make modules to import into this file rather than have one giant file
'''


# function to get commandline arguments and parse them based on the desired functionality
def get_args():
    parser = argparse.ArgumentParser(prog='threatblockr-api.py', description='Query or update the ThreatBlockr Appliance through the terminal')
    subparser = parser.add_subparsers(dest='command')

    # query parser to query a domain or IP address
    query_parser = subparser.add_parser('query', help='Query for domain or IP presence')
    query_parser.add_argument('-d', '--domain', dest='domain', help='Domain you want to query')
    query_parser.add_argument('-i', '--ip-address', dest='ip_addr', help='IP address you want to query')
    query_parser.add_argument('--show-lists', dest='tb_lists', default=True, action='store_true', help='Show the current lists that are present in ThreatBlockr')
    query_parser.add_argument('--file', dest='ip_file', help='Pass in a file with IP addresses to query')

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

    # get reports
    report_parser = subparser.add_parser('report', help='Get report data for the specified report and period')
    report_parser.add_argument('-r', '--report', dest='report_type', help='Report type - e.g. reasons, countries, asns, category')

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
    if (add_to_list.lower() == 'y' or add_to_list.lower() == 'yes'):
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


def file_search(file=''):
    file_list = list()
    blacklist = list()
    allowed = list()

    with open(file, 'r') as f:
        lines = f.readlines()
        for line in lines:
            file_list.append(line.strip())
            results = search(line.strip())
            if results != []:
                blacklist.append(line.strip())
                sleep(1)

    for ip in file_list:
        if ip not in blacklist:
            allowed.append(ip)

    print('\nNot found in any block lists:\n', allowed)

    block_unlisted = input('Do you want to block these IP\'s? [y/n]: ')

    if (block_unlisted.lower() == 'y' or block_unlisted.lower() == 'yes'):
        for ip in allowed:
            update_block(ip, 32, 'received from threat intel')
    else:
        print('Done. Quitting!')


def search(ip='', domain=''):
    data = get_lists()
    all_lists = json.loads(data)
    blacklist = list()
    headers.pop('X-Fields')

    if ip:  
        for i in all_lists:
            if i['listType'] == 'block':
                response = requests.get(f'{base_url}/block-lists/ip/{i["uuid"]}/entries?page=1&perPage=20&search={ip}&sortDirection=ascending', headers=headers).text
                if '"items": []' in response:
                    pass
                else:
                    blacklist.append({i['name']: ip})
                    print(f'Found {ip} in {i["name"]}')

        return blacklist

    elif domain:
        response = requests.get(f'{base_url}{api_endpoints["search_ioc_domain"]}{domain}', headers=headers).text
        print(response)
    else:
        print('Unknown options. Quitting!')


# function to display the currently configured lists in threatblockr
def get_lists():

    # update the headers to include the X-Fields for the query and remove Content-Type
    if 'Content-Type' in headers:
        headers.pop('Content-Type')
    else:
        pass

    headers.update({'X-Fields': 'uuid,name,count,description,listType'})
    response = requests.get(f'{base_url}/lists?iocType=ip', headers=headers).text

    return response


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


# function to run the specified report
def run_report(report):
    
    # remove the Content-Type header
    headers.pop('Content-Type')

    # send a GET request for the report type endpoint
    response = requests.get(f'{base_url}/reports/{report}/top?edgeInstanceUuid={edge_uuid}&preset=last_week&top=10', headers=headers).text
    print(response)


# main function - checks the subcommands and calls the relevant function based on user provided options
def main():
    if options.command == 'query':
        if options.nameservers:
            lookup_dns(options.domain)
        elif options.threatblockr:
            if options.ip_file:
                file_search(file=options.ip_file)
            else:
                search(ip=options.ip_addr, domain=options.domain)
        elif options.tb_lists:
            print(get_lists())
        else:
            pass
    elif options.command == 'allow':
        update_allow(options.ip_addr, options.maskbits, options.description)
    elif options.command == 'block':
        update_block(options.ip_addr, options.maskbits, options.description)
    elif options.command == 'report':
        run_report(options.report_type)
    else:
        pass


if __name__ == '__main__':
    main()
    
