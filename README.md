# threatblockr-api

Python script to interact with the ThreatBlockr API from the terminal.

# Updates

There have been some feature updates!

- The search options have changed to allow you to iterate through all configured block lists for an IP address, and if it's not blocked it will prompt you to block it.
- Also, you can run reports for Reasons, Categories, Countries and ASNs. These reports will give you the total allowed and blocked for the last week.
- The subcommands were split off into their own "modules" and imported into the main file (`threatblocker-api.py`) to clean it up a bit.

## Command Updates

### Query

The `query` command now allows you to query what lists you have configured in your edge instance. This includes both block and allow lists. Everything is return in json format.

Additionally you can now pass in a file containing IP addresses or domain names with `--file`. Using this flag with an IP file will allow you to iterated through all block lists and search for an IP. If it's not found in any block list it will prompt you to block it.

### Update

The `update` command has replaced the `allow` and `block` commands. Those commands were repetitive and I decided to replace them with `update` to keep things in order.

This command will allow you to update allow and blocks lists by adding or removing IP addresses from the lists.

### Report

The `report` command will allow you to run reports on Reasons, Categories, Countries or ASNs. These reports are configured for the last week and will show allowed and blocked hit counts.

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
usage: threatblockr-api.py [-h] {query,update,report} ...

Query or update the ThreatBlockr Appliance through the terminal

positional arguments:
  {query,update,report}
    query               Query for domain or IP presence
    update              Update the specified list
    report              Get report data for the specified report and period

options:
  -h, --help            show this help message and exit
```

Query help menu:

```
python3 threatblockr-api.py query -h
usage: threatblockr-api.py query [-h] [-d DOMAIN] [-i IP_ADDR] [--show-lists] [--file IP_FILE] [-n | -t]

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Domain you want to query
  -i IP_ADDR, --ip-address IP_ADDR
                        IP address you want to query
  --show-lists          Show the current lists that are present in ThreatBlockr
  --file IP_FILE        Pass in a file with IP addresses to query
  -n, --nameservers     Query nameservers/DNS records for domain
  -t, --threatblockr    Query ThreatBlockr for domain
```

Update help menu:

```
python3 threatblockr-api.py update -h
usage: threatblockr-api.py update [-h] [-i IP_ADDR] [-m MASKBITS] [-D DESCRIPTION] [-a | -b | -rb | -ra]

options:
  -h, --help            show this help message and exit
  -i IP_ADDR, --ip-address IP_ADDR
                        IP Address to add to ThreatBlockr list
  -m MASKBITS, --maskbits MASKBITS
                        CIDR notation maskbits - e.g. 24, 32, etc
  -D DESCRIPTION, --description DESCRIPTION
                        Description for the new entry - e.g. "www.example.com"
  -a, --allow           Update the allow list
  -b, --block           Update the block list
  -rb, --remove-block   Remove IP from block list
  -ra, --remove-allow   Remove IP from allow list
```

Report help menu:

```
python3 threatblockr-api.py report -h
usage: threatblockr-api.py report [-h] [-r {reasons,categories,countries,asns}]

options:
  -h, --help            show this help message and exit
  -r {reasons,categories,countries,asns}, --report {reasons,categories,countries,asns}
                        Report type - e.g. reasons, categories, countries, asns
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

Query for single IP address presence in ThreatBlockr:

```
python3 threatblockr-api.py query -t -i 1.10.184.106
Found 1.10.184.106 in CINS Army list
```

Query for ThreatBlockr for IP's in a file, then prompt to block unlisted IP's:

```
python3 threatblockr.py query -t --file ~/temp/royal-short
Found 47.87.229.39 in CISA Alert List
Found 5.181.234.58 in CISA Alert List
Found 45.61.136.47 in CISA Alert List
Found 45.61.136.47 in DomainTools

Not found in any block lists:
 ['1.2.3.4', '5.4.3.2']
Do you want to block these IP's? [y/n]: y
[
    {
        "id": "1.2.3.4/32",
        "address": "1.2.3.4",
        "maskbits": 32,
        "description": "received from threat intel",
        "insertedDatetime": "2023-05-12T15:25:26.000+00:00",
        "expiresDatetime": null
    }
]

[
    {
        "id": "5.4.3.2/32",
        "address": "5.4.3.2",
        "maskbits": 32,
        "description": "received from threat intel",
        "insertedDatetime": "2023-05-12T15:25:26.000+00:00",
        "expiresDatetime": null
    }
]

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
python3 threatblockr-api.py update -i 8.8.8.8 -m 32 -D "google DNS IP" --allow
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

## Remove IP from list (block or allow)

To remove an IP address from either a block list or allow list:

- `-rb` or `--remove-block` will remove from block lists
- `-ra` or `--remove-allow` will remove from allow lists

```
python3 threatblockr.py update -i 1.2.3.4 -m 32 --remove-block
1.2.3.4 was removed from ThreatBlockr!
```
