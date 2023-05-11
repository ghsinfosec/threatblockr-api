import os


def init():
    global headers
    global payload_data
    global base_url
    global api_endpoints

    # initialize variables
    base_url = 'https://admin.threatblockr.com/api/v5'
    
    # need these headers to make API call
    headers = {
            'accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': os.environ.get('THREATBLOCKR_API')}
    
    # endpoints for the API calls that we care about
    api_endpoints = {
            'search_ioc_domain': '/search/ioc/domain/',
            'allow_list_ip': '/allow-lists/ip/<UUID-FOR-ALLOW-LIST>/entries',
            'block_list_ip': '/block-lists/ip/<UUID-FOR-BLOCK-LIST>/entries'
            }
    
    # the payload needed for updating allow and block lists
    payload_data = [
            {
                'id': '',
                'address': '',
                'maskbits': 0,
                'description': '',
                'expiresDatetime': ''
                }
            ]


