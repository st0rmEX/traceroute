# Traceroute
Traceroute is a network diagnostic tool that displays possible routes from your current IP address to a 
desired destination. TTL is set to 30 by default but can be adjusted accordingly. This implementation handles
IPv4, ICMP, and UDP packets.
## Usage
```
python3 traceroute.py [IP Address]
```
For example:
```
python3 traceroute.py 8.8.8.8 
```
Will return the number of hops or routers it takes to connect
from your IP address to Google's public DNS server.
