#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <strings.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <asm/byteorder.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define false 0
#define true 1

/* Trie */
typedef struct Tnode
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
		bit = ip >> (len - i - 1) & 1;
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
	for(i; i < len; i++) {
		t->isEnd = false;
		bit = ip >> (len - i - 1) & 1;
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
	int len = 0, bit = 0, i = 0;
	uint32_t cpy = ip;
	while(cpy) {
		len++;
		cpy >>= 1;
	}
	len = 31;
	while(1) {
		bit = ip >> (len - i - 1) & 1;
		printf("%d", bit);
		if(bit) {
			if(t->right == NULL) break;
			t = t->right;
		}
		if(!bit) {
			if(t->left == NULL) break;
			t = t->left;
		}
		i++;
		//f(t->isEnd) break;
	}
	if (t->interface >= 0) {
		struct route_table_entry *route_entry = malloc(sizeof(struct route_table_entry));
		route_entry->interface = t->interface;
		route_entry->next_hop = t->next_hop;
		return route_entry;
	}
	return NULL;
}


int read_rtable(const char *path, struct route_table_entry *rtable)
{
	FILE *fp = fopen(path, "r");
	int j = 0, i;
	char *p, line[64];

	while (fgets(line, sizeof(line), fp) != NULL) {
		p = strtok(line, " .");
		i = 0;
		while (p != NULL) {
			if (i < 4)
				*(((unsigned char *)&rtable[j].prefix)  + i % 4) = (unsigned char)atoi(p);

			if (i >= 4 && i < 8)
				*(((unsigned char *)&rtable[j].next_hop)  + i % 4) = atoi(p);

			if (i >= 8 && i < 12)
				*(((unsigned char *)&rtable[j].mask)  + i % 4) = atoi(p);

			if (i == 12)
				rtable[j].interface = atoi(p);
			p = strtok(NULL, " .");
			i++;
		}
		j++;
	}
	return j;
}

struct Tnode *parse_trie(struct Tnode *root) {
	for (int i = 0; i < rtable_len; i++) {
		/* Determine mask len */
		int len = 0;
		uint32_t cpy = rtable[i].mask;
		while(cpy) {
			len++;
			cpy >>= 1;
		}
		int len_1 = 0;
		for (int j = 0; j < len; j++) {
			int bit = rtable[i].mask >> (len - j - 1) & 1;
			if(bit) len_1 ++;
		}
		/* Insert */
    	insert(root, rtable[i].prefix, len_1, rtable[i].interface, rtable[i].next_hop);
    	// rtable[i].prefix & rtable[i].mask;
	} 
	return root;
} 
