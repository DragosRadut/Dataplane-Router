#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <arpa/inet.h>
#define false 0
#define true 1
/* ICMP TYPES */
#define REPLY 0
#define TIMEOUT 11
#define UNREACH 3
/* PADDINGS */
#define ip_pad 14
#define icmp_pad 34
#define iphdr_size 20
#define icmp_size 8

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

struct Tnode *root;

/* ARP structs */
struct arp_entry *arp_cache;
int arptable_len;
int arp_cache_len;

static uint16_t ARP_TYPE = 0x608;
static uint16_t ETH_TYPE = 0x0100;
static uint16_t IP4_TYPE = 0x0008;
static uint16_t ARP_RESP = 0x0200;
static uint16_t ARP_REQ = 0x0100;

/* Recieved packets */
struct packet_list {
    int len;
    char buf[MAX_PACKET_LEN];
    uint32_t target;
};
struct packet_list *list;
int packet_list_len;

/* Trie */
struct Tnode
{
	struct Tnode *left;
	struct Tnode *right;	
	uint32_t next_hop;
	int interface;
	int isEnd;
};

struct Tnode *node_create(int interface, uint32_t next_hop)
{
	struct Tnode *t = malloc(sizeof(struct Tnode));
	t->left = t->right = NULL;
	t->isEnd = false;
	t->interface = interface;
	t->next_hop = next_hop;
	return t;
}

void insert(struct Tnode *root, uint32_t ip, int len, int interface, uint32_t next_hop)
{	
	struct Tnode *t = root;
	/* Go on existing pattern */
	int bit = 0, i = 0;
	for(i = 0; i < len; i++) {
		bit = (ip >> i) & 1;
		if(bit) {
			if(t->right == NULL) break;
			t = t->right;
		}
		if(!bit) {
			if(t->left == NULL) break;
			t = t->left;
		}
	}
	if(i == len) return;
	for(; i < len; i++) {
		t->isEnd = false;
		bit = (ip >> i) & 1;
		if(bit) {
			t->right = node_create(interface, next_hop);
			t = t->right;
			continue;
		}
		if(!bit) {
			t->left = node_create(interface, next_hop);
			t = t->left;
			continue;
		}
	}
	t->isEnd = true;
}

struct route_table_entry *find(struct Tnode *root, uint32_t ip) {
	struct Tnode *t = root;
	int len = 0, bit = 0;
	while(len < 32) {
		bit = (ip >> len) & 1;
		printf("%d", bit);
		if(bit) {
			if(t->right == NULL) break;
			t = t->right;
		}
		if(!bit) {
			if(t->left == NULL) break;
			t = t->left;
		}
		len++;
	}
	if (t->isEnd) {
		struct route_table_entry *route_entry = malloc(sizeof(struct route_table_entry));
		route_entry->interface = t->interface;
		route_entry->next_hop = t->next_hop;
		return route_entry;
	}
	return NULL;
}


struct Tnode *parse_trie(struct Tnode *root) {
	for (int i = 0; i < rtable_len; i++) {
		/* Determine mask len */
		int cnt = 0;
		for(int k = 31; k >= 0; k--) {
			int bit = rtable[i].mask >> k;
			if(bit & 1) cnt++;
		}
		/* Insert */
    	insert(root, rtable[i].prefix, cnt, rtable[i].interface, rtable[i].next_hop);
    } 
	return root;
} 

uint8_t* get_arp_mac(uint32_t ip_dest) {
	/* Search cache */
	for (int i = 0; i < arp_cache_len; i++) {
		printf("ARP:%d   in:%d\n", arp_cache[i].ip, ip_dest);
    	if (arp_cache[i].ip == ip_dest) {
    		printf("Found ip entry in mac arpalllll\n");
      		return arp_cache[i].mac;
    	}
	}
	return NULL;
}

void icmp_reply(char* buf, int interface, size_t len) {
	/* Modify L2 */
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	get_interface_mac(interface, eth_hdr->ether_shost);
	/* Modify IP */
	struct iphdr *ip_hdr = (struct iphdr *)(buf + ip_pad);
	ip_hdr->ttl--;
	uint32_t aux = ip_hdr->saddr;
	ip_hdr->saddr = inet_addr(get_interface_ip(interface));
	ip_hdr->daddr = aux;
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t*)ip_hdr, sizeof(struct iphdr)));
	/* Modify ICMP */	
	struct icmphdr *icmp_resp = malloc(sizeof(struct icmphdr));
	icmp_resp->type = REPLY;
	icmp_resp->code = 0;
	icmp_resp->checksum = 0;
	/* Type of ICMP */
	memcpy((char*)icmp_resp + 4, buf + icmp_pad + 4, 2);
	memcpy((char*)icmp_resp + 6, buf + icmp_pad + 6, 2);
	/* ICMP Checksum */
	int data_len =  ntohs(ip_hdr->tot_len) - iphdr_size;
	char* icmp_check_data = malloc(data_len);
	memcpy(icmp_check_data, (char*)icmp_resp, sizeof(struct icmphdr));
	memcpy(icmp_check_data + sizeof(struct icmphdr), (char*)buf + icmp_pad + sizeof(struct icmphdr), data_len - sizeof(struct icmphdr));
	icmp_resp->checksum = htons(checksum((uint16_t*)icmp_check_data, data_len));
	/* Packet */
	char resp[len];
	char* payload = (char *)(buf + icmp_pad + sizeof(struct icmphdr));
	memcpy(resp, (char*)eth_hdr, sizeof(struct ether_header));
	memcpy(resp + ip_pad, (char*)ip_hdr, sizeof(struct iphdr));
	memcpy(resp + icmp_pad, (char*)icmp_resp, sizeof(struct icmphdr));
	memcpy(resp + icmp_pad + sizeof(struct icmphdr), (char*)payload, data_len - sizeof(struct icmphdr));
	send_to_link(interface, (char*)resp, len);
	return;
}

void icmp_error(char* buf, int interface, size_t len, int type) {
	/* Modify L2 */
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	get_interface_mac(interface, eth_hdr->ether_shost);
	/* Modify IP */
	struct iphdr *ip_hdr = (struct iphdr *)(buf + ip_pad);
	struct iphdr *ip_reply = malloc(sizeof(struct iphdr));
	ip_reply->version = 4;
	ip_reply->ihl = 5;
	ip_reply->tos = 0;
	ip_reply->tot_len = htons(2 * (iphdr_size + icmp_size));
	ip_reply->id = 1;
	ip_reply->frag_off = 0;
	ip_reply->ttl = 64;
	ip_reply->protocol = 1;
	ip_reply->saddr = ip_hdr->daddr;
	ip_reply->daddr = ip_hdr->saddr;
	ip_reply->check = 0;
	ip_reply->check = htons(checksum((uint16_t*)ip_reply, sizeof(struct iphdr)));
	/* Modify ICMP */	
	struct icmphdr *icmp_hdr = (struct icmphdr *) (buf + icmp_pad);
	struct icmphdr *icmp_resp = malloc(sizeof(struct icmphdr));
	icmp_resp->type = type;
	icmp_resp->code = 0;
	icmp_resp->checksum = 0;
	/* ICMP Checksum */
	int data_len =  iphdr_size + 8 + icmp_size;
	char* icmp_check_data = malloc(data_len);
	memcpy(icmp_check_data, (char*)icmp_resp, icmp_size);
	memcpy(icmp_check_data + icmp_size, (char*)(ip_hdr), iphdr_size);
	memcpy(icmp_check_data + icmp_size + iphdr_size, (char*)(icmp_hdr), 8);
	icmp_resp->checksum = htons(checksum((uint16_t*)icmp_check_data, data_len));
	/* Packet */
	len = sizeof(struct ether_header) + 2 * iphdr_size + 2 * icmp_size;
	char resp[len];
	memcpy(resp, (char*)eth_hdr, sizeof(struct ether_header));
	memcpy(resp + ip_pad, (char*)ip_reply, iphdr_size);
	memcpy(resp + icmp_pad, (char*)icmp_resp, icmp_size);
	memcpy(resp + icmp_pad + sizeof(struct icmphdr), (char*)ip_hdr, iphdr_size);
	memcpy(resp + icmp_pad + sizeof(struct icmphdr) + iphdr_size, (char*)icmp_hdr, 8);
	send_to_link(interface, (char*)resp, len);
	return;
}

void arp_req(struct ether_header *eth_hdr, struct iphdr *ip_hdr, int interface, uint32_t target) {
	/* Ethernet hdr */
	struct ether_header *eth_resp = malloc(sizeof(struct ether_header));
	get_interface_mac(interface, eth_resp->ether_shost);
	hwaddr_aton("FF:FF:FF:FF:FF:FF", eth_resp->ether_dhost);
	eth_resp->ether_type = ARP_TYPE;
	/* ARP hdr */
	struct arp_header *arp_hdr = malloc(sizeof(struct arp_header));
	arp_hdr->htype = ETH_TYPE;
	arp_hdr->ptype = IP4_TYPE;
	arp_hdr->hlen = (uint8_t)6;
	arp_hdr->plen = (uint8_t)4;
	arp_hdr->op = (uint16_t)ETH_TYPE;
	memcpy(arp_hdr->sha, eth_resp->ether_shost, 6);
	arp_hdr->spa = inet_addr(get_interface_ip(interface));
	arp_hdr->tpa = target;
	/* Packet */
	char resp[sizeof(struct ether_header) + sizeof(struct arp_header)];
	memcpy(resp, (char*)eth_resp, sizeof(struct ether_header));
	memcpy(resp + ip_pad, (char*)arp_hdr, sizeof(struct arp_header));
	printf("ARP request Sent!\n");
	send_to_link(interface, (char*)(resp), sizeof(struct ether_header) + sizeof(struct arp_header));
	return;
}

void arp_reply(char* buf, uint32_t target) {
	/* L2 Response */
	struct route_table_entry *route_entry = find(root, target);
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct ether_header *eth_resp = malloc(sizeof(struct ether_header));
	uint8_t router_mac[6];
	get_interface_mac(route_entry->interface, router_mac);
	memcpy(eth_resp->ether_shost, router_mac, 6);
	memcpy(eth_resp->ether_dhost, eth_hdr->ether_shost, 6);
	eth_resp->ether_type = ARP_TYPE;
	/* ARP hdr */
	struct arp_header *arp_recv = (struct arp_header *) (buf + ip_pad);
	struct arp_header *arp_hdr = malloc(sizeof(struct arp_header));
	arp_hdr->htype = ETH_TYPE;
	arp_hdr->ptype = IP4_TYPE;
	arp_hdr->hlen = (uint8_t)6;
	arp_hdr->plen = (uint8_t)4;
	arp_hdr->op = (uint16_t)ARP_RESP;
	memcpy(arp_hdr->sha, eth_resp->ether_shost, 6);
	arp_hdr->spa = arp_recv->tpa;
	arp_hdr->tpa = target;
	memcpy(arp_hdr->tha, arp_recv->sha, 6);
	/* Packet */
	char resp[sizeof(struct ether_header) + sizeof(struct arp_header)];
	memcpy(resp, (char*)eth_resp, sizeof(struct ether_header));
	memcpy(resp + ip_pad, (char*)arp_hdr, sizeof(struct arp_header));
	send_to_link(route_entry->interface, (char*)(resp), sizeof(struct ether_header) + sizeof(struct arp_header));
	return;
}

void add_arp_entry(char* buf, int interface) {
	arp_cache_len ++;
	arp_cache = realloc(arp_cache, arp_cache_len * sizeof(struct arp_entry));
	struct arp_header *recv = (struct arp_header*)(buf + ip_pad);
	arp_cache[arp_cache_len - 1].ip = (recv->spa);
	memcpy(arp_cache[arp_cache_len - 1].mac, recv->sha, 6);
	return;
}

void add_list_entry(char* buf, int len, uint32_t target) {
	packet_list_len ++;
	list = realloc(list, packet_list_len * sizeof(struct packet_list));
	list[packet_list_len - 1].target = target;
	list[packet_list_len - 1].len = len;
	memcpy(list[packet_list_len - 1].buf, buf, len);
	return;
}

void forward(struct packet_list list) {
	struct ether_header *eth_hdr = (struct ether_header *) list.buf;
	/* Chech packet type */
	struct arp_header *arp_test = (struct arp_header *) (list.buf + ip_pad);
	if(eth_hdr->ether_type == ARP_TYPE && arp_test->op == ARP_REQ) {
		/* ARP REPLY */
		printf("Forward ARP\n");
		arp_reply(list.buf, list.target);
		return;
	}
	struct iphdr *ip_hdr = (struct iphdr *)(list.buf + ip_pad);
	/* Update L2 */
	struct route_table_entry *route_entry = find(root, ip_hdr->daddr);//get_best_route(ip_hdr->daddr);
	get_interface_mac(route_entry->interface, eth_hdr->ether_shost);
	uint8_t *mac_dest = get_arp_mac(list.target);
	memcpy(eth_hdr->ether_dhost, mac_dest, 6);
	/* Reconstruct packet */
	char* payload = (char *)(list.buf + icmp_pad);
	char resp[list.len];
	memcpy(resp, (char*)eth_hdr, sizeof(struct ether_header));
	memcpy(resp + ip_pad, (char*)ip_hdr, sizeof(struct iphdr));
	memcpy(resp + icmp_pad, (char*)payload, list.len - icmp_pad);
	send_to_link(route_entry->interface, (char*)resp, list.len);
	return;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	/* Code to allocate the route tables */
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	arp_cache = malloc(sizeof(struct arp_entry));
	/* DIE is a macro for sanity checks */
	DIE(rtable == NULL, "memory");
	
	/* Detect rtable in use */
	if(argc > 0) {
		if(strcmp("rtable0.txt", argv[1]) == 0) {
			rtable_len = read_rtable("rtable0.txt", rtable);
		}
		else rtable_len = read_rtable("rtable1.txt", rtable);
	}
	
	/* Statics for general use */
	static uint8_t broadcast[6];
	hwaddr_aton("FF:FF:FF:FF:FF:FF", broadcast);
	
	/* Create ARP queue */
	list = malloc(sizeof (struct packet_list));
	
	/* Create and init trie */
	root = node_create(-1, 1);
	root = parse_trie(root);
	
	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		
		/* Read ethernet header */
		struct ether_header *eth_hdr = (struct ether_header *) buf;
		
		/* Check L2 validity */
		uint8_t router_mac[6];
		get_interface_mac(interface, router_mac);
		if(memcmp(router_mac, eth_hdr->ether_dhost, 6) && memcmp(broadcast, eth_hdr->ether_dhost, 6)) {
			/* Drop Packet */
			continue;
		}
		
		/* ARP reply */
		struct arp_header *arp_test = (struct arp_header *) (buf + ip_pad);
		if(eth_hdr->ether_type == ARP_TYPE && arp_test->op == ARP_RESP) {
			add_arp_entry(buf, interface);
			struct arp_header *recv = (struct arp_header*)(buf + ip_pad);
			for(int i = 0; i < packet_list_len; i++) {
				if(list[i].target == recv->spa) {
					forward(list[i]);
				}
			}
			continue;
		}
		
		/* ARP request */
		if(eth_hdr->ether_type == ARP_TYPE && arp_test->op == ARP_REQ) {
			/* Check router is destination */
			if(inet_addr(get_interface_ip(interface)) != arp_test->tpa)
				continue;
			/* Send reply */
			arp_reply(buf, arp_test->spa);
			continue;
		}

		/* Read IP header */
		struct iphdr *ip_hdr = (struct iphdr *)(buf + ip_pad);
	
		/* Check router is destination */
		if(inet_addr(get_interface_ip(interface)) == ip_hdr->daddr && ip_hdr->ttl > 1) {
			icmp_reply(buf, interface, len);
			continue;
		}
	
		/* Verify checksum */
		if(checksum((void *)ip_hdr, sizeof(struct iphdr))) {
			printf("Bad check!\n");
			continue;
		}
	
		/* Verify TTL */
		if(ip_hdr->ttl < 2) {
			icmp_error(buf, interface, len, TIMEOUT);
			continue;
		}
		ip_hdr->ttl --;
		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t*)ip_hdr, sizeof(struct iphdr)));
		
		/* Rtable search */
		struct route_table_entry *route_entry = find(root, ip_hdr->daddr);
		if(route_entry == NULL) {
			/* Destination unreachable */
			icmp_error(buf, interface, len, UNREACH);
			continue;
		}

		/* Forward */
		char* payload = (char *)(buf + icmp_pad);
		char resp[len];
		/* Update L2 */
		get_interface_mac(route_entry->interface, eth_hdr->ether_shost);
		uint8_t *mac_dest = get_arp_mac(route_entry->next_hop);
		if(mac_dest == NULL) {
			/* Create ARP Request */
			add_list_entry(buf, len, route_entry->next_hop);
			arp_req(eth_hdr, ip_hdr, route_entry->interface, route_entry->next_hop);
			continue;
		}
		memcpy(eth_hdr->ether_dhost, mac_dest, 6);
		/* Reconstruct packet */
		memcpy(resp, (char*)eth_hdr, sizeof(struct ether_header));
		memcpy(resp + ip_pad, (char*)ip_hdr, sizeof(struct iphdr));
		memcpy(resp + icmp_pad, (char*)payload, len - icmp_pad);
		send_to_link(route_entry->interface, (char*)resp, len);
	}
}

