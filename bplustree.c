#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <stddef.h>
#include <stdbool.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/ptrace.h>

//sudo cat /sys/kernel/debug/tracing/trace_pipe

#define bpf_printk(fmt, ...)				\
	({						\
	char ____fmt[] = fmt;				\
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
	##__VA_ARGS__);					\
	})


#define NODE_ORDER 4 			//must be hardcoded
#define MAX_TREE_HEIGHT 8 		//must be hardcoded
#define INDEX_MAP_SIZE 65536		//must be hardcoded

struct bplus_tree_info {
	int curr_root;			//initialized to 0
	int curr_h;			//initialized to 0
	int free_indexes_tail;		//initialized to INDEX_MAP_SIZE -1
	int is_full;			//initialized to 0
};

struct bplus_node_entry {
	__u64 pointer;
	__u64 key;
};

struct bplus_node {
	struct bplus_node_entry entry[NODE_ORDER];
};

//this map contains the b+ tree index pages
struct bpf_map_def SEC("maps") index_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct bplus_node),
	.max_entries = INDEX_MAP_SIZE,
};

//this map contains the b+ tree info (1 entry)
struct bpf_map_def SEC("maps") tree_info = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct bplus_tree_info),
	.max_entries = 1,
};

//this map contains the b+ tree free node indexes
struct bpf_map_def SEC("maps") free_index_list = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = INDEX_MAP_SIZE,
};

#define OP_SEARCH 1
#define OP_INSERT 2
#define OP_DELETE 3

struct payload {
	__u32 key;
};

static inline __u64 __bplus_process(int cmd, __u64 key, __u8 *data, int len) {
	__u32 zero = 0;
	struct bplus_tree_info *info = NULL;
	struct bplus_tree_info updated_info = {};
	struct bplus_node *node = NULL;
	int node_index = 0;
	__u64 data_pointer = 0;
	int is_leaf = 0;
	int node_traversed[MAX_TREE_HEIGHT] = {0};
	int i=0, j=0;

	info = bpf_map_lookup_elem(&tree_info, &zero);
	if (!info) {
		return XDP_ABORTED;
	}
	
	__builtin_memcpy(&updated_info, info, sizeof(struct bplus_tree_info));

	//all operations need to first search for the leaf node in which 
	//we search/insert/delet a key. we always start from the root	
	node_index = info->curr_root;
	
	for (i=0; i<MAX_TREE_HEIGHT; i++) {
		if (i==info->curr_h-1){
			is_leaf = 1;
		}
    		node = bpf_map_lookup_elem(&index_map, &node_index);

		if (!node) {
			return XDP_ABORTED;
		}

		if (node->entry[NODE_ORDER].key == 0) {
			//node is empty
			break;
		}
		node_traversed[i] = node_index;

		for (j=0; j<NODE_ORDER-1; j++) {
			if (is_leaf == 0) {
				//for now we implement a linear search in the node
				if (key < node->entry[j].key) {
					node_index = node->entry[j].pointer;
					break;
				} else {
					//(search key == curr key) or
					if ((key == node->entry[j].key) || 
					//(search key > curr_key) and (curr key == last key)
					  ( (j == node->entry[NODE_ORDER-1].key) || (j == NODE_ORDER-2)) ) { 
						node_index = node->entry[j+1].pointer;
						break;	
					}
				}
			}
			else {
				//leaf node
				if (cmd == OP_SEARCH) {
					//exact match of the search key in the leaf node
					for (j=0; j<NODE_ORDER-2; j++) {
						if (key == node->entry[j].key) {
							data_pointer = node->entry[j].pointer;
							break;
						} 				
					}	
				}
			}
		}

		if (is_leaf) {
		       break;
		}	       
	}

	if (cmd == OP_SEARCH) {
		return data_pointer; 
	} else if (cmd == OP_INSERT) {
		//node == leaf node
		int num_of_keys_in_node = node->entry[NODE_ORDER -1].key;
		__u64 free_data_index = 1234;
		int memsize = 0;
		if (num_of_keys_in_node == NODE_ORDER - 1) { //the leaf node is full
			//TODO split!!
		} else {
			//ordered insertion in array
			for (i==0; i<NODE_ORDER-2; i++) {

				if (i == num_of_keys_in_node-1) {//empty entry
					node->entry[i].key = key;	
					break;
				}

				if (key < node->entry[i].key) {
					//move and set
					//TODO get free data map idx
					//TODO insert in data map
					memsize = sizeof(struct bplus_node_entry)*(num_of_keys_in_node-i);
					
					__builtin_memcpy(&(node->entry[i+1]), &(node->entry[i]), memsize);
					node->entry[i].pointer = free_data_index;
					node->entry[i].key = key;
				}
			}
		}
		return free_data_index;	
	} else if (cmd == OP_DELETE) {
		//index == leaf node index
		return XDP_ABORTED;
	} else {
		return XDP_ABORTED;
	}
}


SEC("xdp")
int ingress(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip =  data + sizeof(struct ethhdr);
	struct udphdr *udp = (void*)ip + sizeof(struct iphdr);
	struct payload *p = (void*)udp + sizeof(struct udphdr);
	__u32 offset = 0;
	__u64 ret = 0;
	__be32 saddr = 0, daddr = 0;
        __be16 sport = 0, dport = 0;
	__u8 h_source[6] = {0}, h_dest[6] = {0}; 

	offset = sizeof(struct ethhdr);

	if (data + offset > data_end) {
		return XDP_DROP;
	}
	__builtin_memcpy(h_dest, eth->h_dest, 6);
	__builtin_memcpy(h_source, eth->h_source, 6);

	if (eth->h_proto == __constant_htons(ETH_P_IP)) {
		offset += sizeof(struct iphdr);
		if (data + offset > data_end) {
			return XDP_DROP;
		}

		if (ip->ihl != 5) {
			return XDP_DROP;
		}

		saddr = ip->saddr;
		daddr = ip->daddr;	

		if (ip->protocol == IPPROTO_TCP) {
			return XDP_PASS; 
		}
		else if (ip->protocol == IPPROTO_UDP) {
			offset += sizeof(struct udphdr);
		}
		else {
			return XDP_PASS;
		} 

		if (data + offset > data_end) {
			return XDP_DROP;
		}

		sport = udp->source;
		dport = udp->dest;

		if (udp->dest != 0xaaaa) {
			return XDP_PASS;
		} else {
			offset += sizeof(struct payload);

			if (data + offset > data_end) {
				return XDP_DROP;
			}	

			//val = __bplus_search(p->key);
			ret = __bplus_process(OP_SEARCH, p->key, NULL, 0);
		}

		__builtin_memcpy(eth->h_dest, h_source, 6);
		__builtin_memcpy(eth->h_source, h_dest, 6);
		ip->saddr = daddr;
		ip->daddr = saddr;
		udp->source = dport;
		udp->dest = sport;

		
		
		if (!ret) { 
			__u32 tmp = 0;
			__builtin_memcpy(p, &tmp, 4);
		} else {
			//__builtin_memcpy(p, val, 4);
			return XDP_ABORTED;
		}

		return XDP_TX;

	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
