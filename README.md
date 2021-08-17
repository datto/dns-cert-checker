# DNS Certificate Checker
## Overview
DNS Certertifcate Checker is a tool designed to scan _all_ TLS enabled services under a given DNS zone. By sourcing information from A and CNAME records directly from authoritative DNS servers, it can check a given IP address for all hostnames that it should serve, according to information sourced from the DNS server(s).

## Requirements
* python >= 3.7
* See requirements.txt

## Installation
` python3 -m pip install -r requirements.txt`

## Usage
Once a valid configuration file present at `config.json` (see `config.json.example` for inspiration), the next step is to get exports of the DNS zones to be scanned. If the same host will be used to fetch zone transfers and scan for TLS services, `dns_cert_checker.py` can be invoked on its own. Else, if a seperate host is used for exporting DNS zone transfers, `fetch_zone_transfers.py` should be invoked on the approved host, and the resulting JSON file should be supplied to the execution of `dns_cert_checker.py` via the `--from-zones-json` argument.

## Considerations
By default, this program will request zone transfers for each provided zone for a given name server. The host running this program must have its IP address approved to request zone transfers from all configured nameservers. **This privilege should not be taken lightly**. Although zone transfers are extremely useful in this context, they're also a fantastic resource for any attackers that can communicate with the DNS server. Be vigilant in your DNS server configuration, and [keep a lean list of hosts approved to request zone transfers](https://docs.microsoft.com/en-us/services-hub/health/remediation-steps-ad/configure-all-dns-zones-only-to-allow-zone-transfers-to-specified-ip-addresses).

If you'd rather not perform a zone transfer at run-time, the accompanying script `fetch_zone_transfers.py` can be used to generate a  JSON  listing of zone records, readable by DNS Certificate Checker with the `--from-zones-json` command-line argument.

Wildcard DNS records are not conclusively evaluated, as they can provide an infinite number of certificates, depending on the host's configuration. At this time, DNS Certificate Checker simply checks against the `*` subdomain of a given wildcard record. Note that this will be fine if the wildcard target simply serves a wildcard certificate for the (sub)domain.

## Arguments
### `dns-cert-checker.py`
|short name|long name|help text|
|-|-|-|
|`-o`|`--output_csv`|If set, output a CSV of all detected certificate warnings/errors that were discovered
|N/A|`--from-zones-json`|If set, load zone information from the provided JSON file instead of requesting zone transfers from nameservers at runtime

### `fetch_zone_transfers.py`
|short name|long name|help text|
|-|-|-|
|`-o`|`--output_file`|If set, output the resulting JSON to a file, rather than `/dev/stdout`

## Configuration File Options
A sample configuration file is present at `config.json.example`.

|key name|value definition|value type|value default|
|-|-|-|-|
|`log_level`|The level to use in the logger's call to `setLevel`|int|30 (logging.WARNING)|
|`ssl_ports`|A list of ports to check when scanning hosts|List[int]|[443]|
|`min_time_to_expiration`|The minimum number of seconds of certificate validity to not consider it close to expiration|int|2592000 (30 days)|
|`nameserver_zones`|A dict of DNS `{server: [zone_0, zone_1, ..., zone_n]}` items, where `server` is the IP address of an authoritative DNS server for all zones below it|Dict[str, List[str]]|N/A|
|`lookup_nameservers`|If specified, a list of nameservers to use, rather than the operating system's default configuration|Optional[List[str]]|N/A|

## SSLyze Tunables
Documentation on SSLyze can be found here:
https://nabla-c0d3.github.io/sslyze/documentation/

### Scanner
|Parameter Name|Default Value                |
|-----------------------------------------|--|
|`per_server_concurrent_connections_limit`|5 |
|`concurrent_server_scans_limit`          |10|


### ServerConnectivityTester
ServerConnectivityTesters take in a ServerNetworkLocation (including hostname, port, and ip), and optionally a ServerNetworkConfiguration.

The latter value allows for fine-grained control over how the connectivity tester will connect to the server. The program does not currently supply a value for ServerNetworkConfiguration.
