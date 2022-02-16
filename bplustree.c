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

#define DEBUG 1

#define bpf_printk(fmt, ...)				\
		({						\
		char ____fmt[] = fmt;				\
		bpf_trace_printk(____fmt, sizeof(____fmt),	\
		##__VA_ARGS__);					\
		})
	
#ifdef DEBUG
#define BPF_DEBUG(str, ...) bpf_printk(str, ##__VA_ARGS__)
#else
#define BPF_DEBUG(str, ...) do { } while(0)
#endif

#define NODE_ORDER 8 			//must be hardcoded
#define MAX_TREE_HEIGHT 8 		//must be hardcoded
#define INDEX_MAP_SIZE 65536		//must be hardcoded

struct bplus_tree_info {
	__u32 curr_root;		//initialized to 1
	__u32 curr_h;			//initialized to 1
	__u32 free_indexes_tail;	//initialized to INDEX_MAP_SIZE -1
	__u32 is_full;			//initialized to 0
};

struct bplus_node_entry {
	__u32 pointer;
	__u32 key;
};

struct bplus_node {
	struct bplus_node_entry entry[NODE_ORDER];
};

//this map contains the b+ tree index pages
struct bpf_map_def SEC("maps") index_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct bplus_node_entry)*NODE_ORDER,
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

#define OP_SEARCH 0x00000001
#define OP_INSERT 0x00000002
#define OP_DELETE 0x00000003

struct payload {
	__u32 cmd;
	__u32 key;
};

static inline __u64 __bplus_process(__u32 cmd, __u64 key, __u8 *data, int len) {
	__u32 zero = 0;
	struct bplus_tree_info *info = NULL;
	struct bplus_tree_info updated_info = {};
	struct bplus_node *node = NULL;
	__u32 node_index = 0;
	__u32 data_pointer = 0;
	int is_leaf = 0;
	int node_traversed[MAX_TREE_HEIGHT] = {0};
	int i=0, j=0;

	info = bpf_map_lookup_elem(&tree_info, &zero);
	if (!info) {
		return 0;
	}
	
	__builtin_memcpy(&updated_info, info, sizeof(struct bplus_tree_info));

	//all operations need to first search for the leaf node in which 
	//we search/insert/delete a key. we always start from the root	
	node_index = info->curr_root;

	if (node_index == 0) {
		//it meens we have not initialized the info map yet
		BPF_DEBUG("the tree is not initialized. doing nothing ...");
		return 0;
	}
	
	for (i=0; i<MAX_TREE_HEIGHT; i++) {
		if (i==info->curr_h-1){
			is_leaf = 1;
		}
    		node = bpf_map_lookup_elem(&index_map, &node_index);

		if (node == NULL) {
			return 0;
		}
		
		BPF_DEBUG("searching in node %d", node_index);
		if (node->entry[NODE_ORDER-1].key == 0) {
			//node is empty
			BPF_DEBUG("the node is empty");
			break;
		}
		node_traversed[i] = node_index;

		if (is_leaf == 0) {
			BPF_DEBUG("the node is not a leaf");
			for (j=0; j<NODE_ORDER-1; j++) {
				//for now we implement a linear search in the node
				//TODO binry search ?
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
		}
		else {
			//leaf node
			BPF_DEBUG("the node is a leaf");
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
		

		if (is_leaf) {
			BPF_DEBUG("leaf node. breakingthe external loop");
		        break;
		}	       
	}

	BPF_DEBUG("the node related to the key is %d", node_index);

	if (cmd == OP_SEARCH) {
		BPF_DEBUG("SEARCH cmd received");
		return data_pointer; 
	} else if (cmd == OP_INSERT) {
		BPF_DEBUG("INSERT cmd received");
		if (data_pointer) {
			bpf_printk("key already in. doing nothing ...");
			return data_pointer;
		}
		//node == leaf node
		int num_of_keys_in_node = node->entry[NODE_ORDER -1].key;
		__u64 free_data_index = 1234;
		int inserted;
		if (num_of_keys_in_node == NODE_ORDER - 1) { //the leaf node is full
			BPF_DEBUG("the node is full: SPLIT!");
			//TODO split!!
		} else {
			//ordered insertion in array
			BPF_DEBUG("the node is not full: ORDERED INSERTION!");
			struct bplus_node updated_node = {} ;
			for (i==0; i<NODE_ORDER-2; i++) {
				if (i == num_of_keys_in_node) {
					if (!inserted) {
						updated_node.entry[i].key = key;	
						updated_node.entry[i].pointer = free_data_index;
					}
					break;
				}

				if (key > node->entry[i].key) {
					updated_node.entry[i].key = node->entry[i].key;
					updated_node.entry[i].pointer = node->entry[i].pointer; 
				}
				if ((key < node->entry[i].key)) {
					//move and set
					//TODO get free data map idx
					//TODO insert in data map
					if (!inserted) {
						updated_node.entry[i].pointer = free_data_index;
						updated_node.entry[i].key = key;
						updated_node.entry[NODE_ORDER-1].key++;
						inserted = 1;
					}
					updated_node.entry[i+1].pointer = node->entry[i].pointer;
					updated_node.entry[i+1].key = node->entry[i].key;
				}
			}
			BPF_DEBUG("insertion: updating node %d", node_index);
			bpf_map_update_elem(&index_map, &node_index, &updated_node, 0);
		}
		return free_data_index;	
	} else if (cmd == OP_DELETE) {
		BPF_DEBUG("DELETE cmd received");
		//index == leaf node index
		return 0;
	} else {
		BPF_DEBUG("unrecognized command. nothing to do ...");
		return 0;
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

			BPF_DEBUG("received command %d key %d", p->cmd, p->key);
			//val = __bplus_search(p->key);
			ret = __bplus_process(p->cmd, p->key, NULL, 0);
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
