# Router Dataplane
## Description
The entire project stands under the copyright of University Politehnica of Bucharest, PCOM 2023, being a graded assignment. 
The implementation uses Miniet for simulating the network in which the router operates. 
The implementation is targeted at constructing the dataplane of a router which is responsible with forwarding.
The following components are implemented:
* Forwarding
* LPM (Longest Prefix Match)
* ARP
* ICMP

## Usage
* Start Mininet topology:
```
sudo python3 topo.py
# topology is considered as follows:
host0                           host2     
      \                       /
       router0 ------- router1 
      /                       \
host1                           host3
```
* Start router:
```
make run_router0
make run_router1
```
* Commands for clients:
```
ping, arping, netcat
```

## Structures
Located and described in `include` dir.

## Forwarding
### Workflow:
* check Layer2 data <=> packet has router or broadcast as destination
* chech packet type: ARP / ICMP
* verfiy Checksum & TTL
* modify IP header (TTL & Checksum) and Ethernet header (detination & source)
* packet reconstruction: ` ETH_HDR | IP_HDR | PAYLOAD` => sent to next hop

## LPM
### Trie implementation
* initialize with parse_trie() which creates new nodes in trie for each entry in routing table
* address addition works on binary tree model
* representation: address "addr/len" = firest len bits in binary form of addr

## ARP
### Received
* router can interpret REQUEST/REPLY
* REPLY: cache mac address recieved and send packets waiting for that address
* REQUEST: if router is destination, send ARP REPLY
### Sent
* send ARP REQUEST if the mac address asociated with the destination ip of the packet recieved isnt's known and add packets with that target to a waiting list
* send ARP REPLY if router is target

## ICMP
* if router is destination of icmp, create and send icmp_reply()
* TIMEOUT if TTL < 2
* DESTINATION UNREACHABLE if destination can't be found in routing table
