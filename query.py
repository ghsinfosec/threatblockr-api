import globals
import json
import requests
import subprocess
import update
from time import sleep


globals.init()


def setup_args(subparser):
    query_parser = subparser.add_parser('query', help='Query for domain or IP presence')
    query_parser.add_argument('-d', '--domain', dest='domain', help='Domain you want to query')
    query_parser.add_argument('-i', '--ip-address', dest='ip_addr', help='IP address you want to query')
    query_parser.add_argument('--show-lists', dest='tb_lists', default=True, action='store_true', help='Show the current lists that are present in ThreatBlockr')
    query_parser.add_argument('--file', dest='ip_file', help='Pass in a file with IP addresses to query')

    query_group = query_parser.add_mutually_exclusive_group()
    query_group.add_argument('-n', '--nameservers', action='store_true', help='Query nameservers/DNS records for domain')
    query_group.add_argument('-t', '--threatblockr', action='store_true', help='Query ThreatBlockr for domain')


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
                    update.add(ip, 32, domain, globals.api_endpoints['allow_list_ip'])
        # update block list
        elif allow_or_block.lower() == 'block':
            for items in ip_list:
                for ip in items:
                    update.add(ip, 32, domain, globals.api_endpoints['block_list_ip'])
        # reject unknown options and quit
        else:
            print('Option not allowed. Quitting!')

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
            update.add(ip, 32, 'received from threat intel', globals.api_endpoints['block_list_ip'])
    else:
        print('Done. Quitting!')


def search(ip='', domain=''):
    data = get_lists()
    all_lists = json.loads(data)
    blacklist = list()
    globals.headers.pop('X-Fields')

    if ip:  
        for i in all_lists:
            if i['listType'] == 'block':
                response = requests.get(f'{globals.base_url}/block-lists/ip/{i["uuid"]}/entries?page=1&perPage=20&search={ip}&sortDirection=ascending', headers=globals.headers).text
                if '"items": []' in response:
                    pass
                else:
                    blacklist.append({i['name']: ip})
                    print(f'Found {ip} in {i["name"]}')

        return blacklist

    elif domain:
        response = requests.get(f'{globals.base_url}{globals.api_endpoints["search_ioc_domain"]}{domain}', headers=globals.headers).text
        print(response)
    else:
        print('Unknown options. Quitting!')


# function to display the currently configured lists in threatblockr
def get_lists():

    # update the headers to include the X-Fields for the query and remove Content-Type
    if 'Content-Type' in globals.headers:
        globals.headers.pop('Content-Type')
    else:
        pass

    globals.headers.update({'X-Fields': 'uuid,name,count,description,listType'})
    response = requests.get(f'{globals.base_url}/lists?iocType=ip', headers=globals.headers).text

    return response


def run(args):
    if args.nameservers:
        lookup_dns(args.domain)
    elif args.threatblockr:
        if args.ip_file:
            file_search(file=args.ip_file)
        else:
            search(ip=args.ip_addr, domain=args.domain)
    elif args.tb_lists:
        print(get_lists())
    else:
        pass
    

