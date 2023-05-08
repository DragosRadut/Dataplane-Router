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
```sudo python3 topo.py
# topology is considered as follows:
host0                           host2     
      \                       /
       router0 ------- router1 
      /                       \
host1                           host3
````
* Start router:
```
make run_router0
make run_router1
```
* Commands for clients:
```ping, arping, netcat```

## Structures
Toate structurile cu instantiere unica se initializeaza inainte de intrarea in loop-ul de "listen" : route table, arp_cache, list (packet queue) si root (LPM trie).

## Forwarding
### Workflow:
* se verifica L2 data <=> pachetul are ca destinatie router-ul curent sau broadcast
* se verifica tipul pachetului: ARP / ICMP (necesita interpretare)
* se verifica checksum, ttl
* se cauta datele necesare pentru modificari
* se fac modificarile necesare la nivelul IP (ttl si checksum) si ethernet (destinatie si sursa)
* reconstructia pachetului: ` ETH_HDR | IP_HDR | PAYLOAD` care se va trimite spre next_hop pe interfata corecta

## LPM
### Trie implementation
* initializarea sa realizeaza prin functia parse_trie() introduce pentru fiecare linie din tabela de rutare nodurile noi
* o adresa introdusa se interpreteaza pe modelul arborelui binar
* diferentierea la niveul mastii se face prin lungimea mastii
* astfel, adresa "addr" cu masca /len se reprezinta ca primii len biti din forma binara a addr
* introducand practic prefixul impreuna cu masca, cautarea se va realiza eficient, parcurgand doar arborele prin urmarea adresei cautate pana la o frunza

## ARP
### Received
* router-ul poate interpreta REQUEST/REPLY
* pentru REPLY, router-ul memoreaza in cache mac-ul primit si trimite pachetele aflate in asteprate pe acea adreasa
* pentru REQUEST, router-ul va interpreta doar in cazul in care el este destinatia si va trimite un ARP REPLY
### Sent
* router-ul va trimite un ARP REQUEST in cazul in care mac-ul asociat adresei ip destinatie nu este cunoscut, punand in coada de asteptare pachetele cu destinatia respectiva
* va trimite un ARP REPLY daca el este target-ul request-ului primit

## ICMP
* in cazul in care router-ul este destinatia unui pachet icmp, va trimite un icmp_reply()
* va trimite TIMEOUT in cazul unui ttl < 2
* va trimite DESTINATION UNREACHABLE in cazul in care nu gaseste intrarea in tabela de rutare
