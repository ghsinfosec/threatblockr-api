# threatblockr-api

Python script to interact with the ThreatBlockr API from the terminal.

# Setup

```
git clone https://github.com/ghsinfosec/threatblocker-api.git
pip install requests
```

# Other Requirements

**API Key**

You'll need an API key as well as add `export THREATBLOCKR_API=<YOUR-API-KEY>` to your `.bashrc` for the API calls to work.

**UUID's for Allow/Block Lists**

Each allow list and block list have a UUID. The easiest approach is to just use one allow list and one block list which you can get from the lists URL in the web console.

# Usage

General help menu:
```
python3 threatblockr-api.py -h
usage: threatblockr-api.py [-h] {query,allow,block} ...

Query or update the ThreatBlockr Appliance through the terminal

positional arguments:
  {query,allow,block}
    query              Query for domain or IP presence
    allow              Update the allow list
    block              Update the block list

options:
  -h, --help           show this help message and exit
```

Query help menu:
```
python3 threatblockr-api.py query -h
usage: threatblockr-api.py query [-h] [-d DOMAIN] [-i IP_ADDR] [-n | -t]

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Domain you want to query
  -i IP_ADDR, --ip-address IP_ADDR
                        IP address you want to query
  -n, --nameservers     Query nameservers/DNS records for domain
  -t, --threatblockr    Query ThreatBlockr for domain
```

Allow help menu:
```
python3 threatblockr-api.py allow -h
usage: threatblockr-api.py allow [-h] [-i IP_ADDR] [-m MASKBITS] [-D DESCRIPTION]

options:
  -h, --help            show this help message and exit
  -i IP_ADDR, --ip-address IP_ADDR
                        IP Address to add to ThreatBlockr list
  -m MASKBITS, --maskbits MASKBITS
                        CIDR notation maskbits - e.g. 24, 32, etc
  -D DESCRIPTION, --description DESCRIPTION
                        Description for the new entry - e.g. "www.example.com"
```

Block help menu:
```
python3 threatblockr-api.py block -h
usage: threatblockr-api.py block [-h] [-i IP_ADDR] [-m MASKBITS] [-D DESCRIPTION]

options:
  -h, --help            show this help message and exit
  -i IP_ADDR, --ip-address IP_ADDR
                        IP Address to add to ThreatBlockr list
  -m MASKBITS, --maskbits MASKBITS
                        CIDR notation maskbits - e.g. 24, 32, etc
  -D DESCRIPTION, --description DESCRIPTION
                        Description for the new entry - e.g. "www.example.com"
```

## Querying domains and IP addresses

Query for domain presence in ThreatBlockr:
```
python3 threatblockr-api.py query -t -d google.com
==[ Searching ThreatBlockr IOC list for google.com ]==

{
    "domain": "google.com",
    "blockListHistory": [],
    "onBlockList": false
}
```

Query for IP address presence in ThreatBlockr:
```
python3 threatblockr-api.py query -i 8.8.8.8
==[ Searching ThreatBlockr IOC list for 8.8.8.8 ]==

{
    "asn": {
        "asn": 15169,
        "name": "Google LLC"
    },
    "address": "8.8.8.8",
    "country": "United States",
    "blockListHistory": [
        {
            "insertDateTime": "2022-06-21 09:24:24",
            "removeDateTime": null,
            "source": "Malware Patrol Enterprise"
        }
    ],
    "onBlockList": true,
    "onThreatList": false,
    "threatListHistory": [],
    "threatListScores": {}
}
```

Query DNS records for a domain:
```
python3 threatblockr-api.py query -n -d miro.com     
54.246.153.150
63.33.95.151
34.252.232.28                     
52.16.59.141                        
34.252.96.110          
34.248.151.221                    
99.80.212.165                                               
63.33.54.20                    
Do you want to update the ThreatBlockr lists? [y/n]: y
Allow list or block list? [allow/block]: allow
[
    {
        "id": "54.246.153.150/32",
        "address": "54.246.153.150",
        "maskbits": 32,            
        "description": "miro.com",
        "insertedDatetime": "2022-11-16T20:03:55.000+00:00",
        "expiresDatetime": null                             
    }                          
]    
                                                                   
[
    {
        "id": "63.33.95.151/32",
        "address": "63.33.95.151",
        "maskbits": 32,          
        "description": "miro.com",
        "insertedDatetime": "2022-11-16T20:03:55.000+00:00",
        "expiresDatetime": null                             
    }                          
]
...
```

The DNS record query also asks you whether or not you want to update a list (allow or block), and will proceed to update the relevant list based on your responses. If you answer `n` or `no` it will just quit.

Also, by setting `expiresDatetime` to `null` will set the entry to never expire.

## Allow/Block IP address

The functionality of these two commands is the same, the only difference is the command itself - either `allow` or `block`.

Add an IP address to the Allow IP List:
```
python3 threatblockr-api.py allow -i 8.8.8.8 -m 32 -D "google DNS IP"        
[
    {
        "id": "8.8.8.8/32",
        "address": "8.8.8.8",
        "maskbits": 32,
        "description": "google DNS IP",
        "insertedDatetime": "2022-11-16T20:08:42.000+00:00",
        "expiresDatetime": null
    }
]
```
