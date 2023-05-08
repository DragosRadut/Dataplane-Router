#include <unistd.h>
#include <stdint.h>

#ifndef TRIE_H
#define TRIE_H

struct Tnode;

/* create  */
extern struct Tnode *node_create(int interface, uint32_t next_hop);
/* insert */
extern void insert(struct Tnode *root, uint32_t ip, int len, int interface, uint32_t next_hop);

/* find */
extern struct route_table_entry *find(struct Tnode *root, uint32_t ip);

/* return a true value if and only if the queue is empty */
extern struct Tnode *parse_trie(struct Tnode *root);

#endif
