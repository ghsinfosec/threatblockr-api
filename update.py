import globals
import requests


globals.init()


def setup_args(subparser):
    # update parser to update the specified list for an IP address
    update_parser = subparser.add_parser('update', help='Update the specified list')
    update_parser.add_argument('-i', '--ip-address', dest='ip_addr', help='IP Address to add to ThreatBlockr list')
    update_parser.add_argument('-m', '--maskbits', dest='maskbits', type=int, help='CIDR notation maskbits - e.g. 24, 32, etc')
    update_parser.add_argument('-D', '--description', dest='description', help='Description for the new entry - e.g. "www.example.com"')

    update_group = update_parser.add_mutually_exclusive_group()
    update_group.add_argument('-a', '--allow', action='store_true', help='Update the allow list')
    update_group.add_argument('-b', '--block', action='store_true', help='Update the block list')
    update_group.add_argument('-rb', '--remove-block', dest='remove_block', action='store_true', help='Remove IP from block list')
    update_group.add_argument('-ra', '--remove-allow', dest='remove_allow', action='store_true', help='Remove IP from allow list')


# function to update the specified IP list 'API Python Script'
def update(ip, maskbits, description, tblist):
    globals.payload_data[0]['address'] = ip
    globals.payload_data[0]['maskbits'] = int(maskbits)
    globals.payload_data[0]['description'] = description 

    # send a POST request for the specified IP list API call
    response = requests.post(f'{globals.base_url}{tblist}', headers=globals.headers, json=globals.payload_data).text
    print(response)


def unblock(ip, maskbits, tblist):
    if 'Content-Type' in globals.headers:
        globals.headers.pop('Content-Type')
    else:
        pass

    response = requests.delete(f'{globals.base_url}{tblist}/{ip}/{maskbits}', headers=globals.headers)

    if response.status_code == 200:
        print(f'{ip} was removed from ThreatBlockr!')
    else:
        print(response.text)

def run(args):
    if args.allow:
        update(args.ip_addr, args.maskbits, args.description, globals.api_endpoints['allow_list_ip'])
    elif args.block:
        update(args.ip_addr, args.maskbits, args.description, globals.api_endpoints['block_list_ip'])
    elif args.remove_block:
        unblock(args.ip_addr, args.maskbits, globals.api_endpoints['block_list_ip'])
    elif args.remove_allow:
        unblock(args.ip_addr, args.maskbits, globals.api_endpoints['allow_list_ip'])
    else:
        pass


