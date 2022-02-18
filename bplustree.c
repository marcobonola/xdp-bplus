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
#define INDEX_MAP_SIZE 16		//must be hardcoded

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

//this map contains the b+ tree free node indexes
struct bpf_map_def SEC("maps") free_index_list = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = INDEX_MAP_SIZE,
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
	int nodes_traversed[MAX_TREE_HEIGHT+1] = {0};
	int nodes_traversed_count = 0;
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
		BPF_DEBUG("the tree is not initialized. doing nothing ...\n");
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
		
		BPF_DEBUG("searching in node %d\n", node_index);
		BPF_DEBUG("storing node idx %d in stack position %d\n", node_index, i+1);
		nodes_traversed[i+1] = node_index;
		nodes_traversed_count++;

		if (node->entry[NODE_ORDER-1].key == 0) {
			//node is empty
			BPF_DEBUG("the node is empty\n");
			break;
		}
		if (is_leaf == 0) {
			BPF_DEBUG("the node is not a leaf\n");
			for (j=0; j<NODE_ORDER-1; j++) {
				//for now we implement a linear search in the node
				//TODO binry search ?
				BPF_DEBUG("j %d node key %d\n", j, node->entry[j].key);
				if (key < node->entry[j].key) {
					node_index = node->entry[j].pointer;
					BPF_DEBUG("LESS. search key %d, key %d, go to node %d\n", key, node->entry[j].key, node_index);
					break;
				} else {
					//(search key == curr key) or
					if ((key == node->entry[j].key) || 
					//(search key > curr_key) and (curr key == last key)
					  ( (node->entry[j].key == 0) || (j == NODE_ORDER-2)) ) { 
						node_index = node->entry[j].pointer;
						BPF_DEBUG("EQUAL or LAST. search key %d, key %d, go to node %d\n", key, node->entry[j].key, node_index);
						break;	
					}
				}
			}
		}
		else {
			//leaf node
			BPF_DEBUG("the node is a leaf\n");
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
			BPF_DEBUG("leaf node. breaking the external loop\n");
		        break;
		}	       
	}

	//"node" is the leaf node in which we search/insert/delete the key
	//if data_pointer != 0 it means we actually found the key. 
	BPF_DEBUG("the node related to the key is %d\n", node_index);

	if (cmd == OP_SEARCH) {
		BPF_DEBUG("SEARCH cmd received\n");
		return data_pointer; 
	} else if (cmd == OP_INSERT) {
		BPF_DEBUG("INSERT cmd received\n");
		__u64 free_data_index = 1234;
		int need_a_new_root = 0;
		int insertion_idx = 0;
		__u32 *free_idx = NULL;
		struct bplus_node * free_node = NULL;
		__u32 new_node_idx;
		int num_of_keys_in_node = 0;
		__u32 left_child=0, right_child=0;

		if (data_pointer) {
			bpf_printk("key already in. doing nothing ...\n");
			return data_pointer;
		}

		//at the beginning of this loop key is the insert key. at every next iteration
		//key will be the median node (if any) to be inserted in the parent node.
		//this loop ends at the first traversed node in the stack. if we still need to split the last
		//node (i.e. the root) we need a new root node (see at the end of this loop)
		
		int initial_nodes_traversed_count = nodes_traversed_count; 
		int kk;

		BPF_DEBUG("initial nodes traversed count %d\n", initial_nodes_traversed_count);

		for (kk=0; kk<MAX_TREE_HEIGHT; kk++) {
			node_index = nodes_traversed[initial_nodes_traversed_count-kk];
			node = bpf_map_lookup_elem(&index_map, &(node_index));
			BPF_DEBUG("recursive insertion loop. node_idx %d left_child %d right child %d\n", 
									node_index, left_child, right_child);
			if (!node) {
				BPF_DEBUG("error in reading the node in the traversed node stack\n");
				return 0;
			}
			num_of_keys_in_node = node->entry[NODE_ORDER-1].key;
			if ((num_of_keys_in_node < 0) || (num_of_keys_in_node >= NODE_ORDER)) {
				BPF_DEBUG("something strange with the key counter in node. aborting....\n");
				return 0;
			}
			if (num_of_keys_in_node == (NODE_ORDER - 1)) { //the leaf node is full
				//TODO do I need an extra entry? Maybe I can use the last one, it is rewritten anyway...
				struct bplus_node_entry extra_node_entry = {};

				BPF_DEBUG("the node is full. finding the index where the new key should be stored\n");
				for (i=0; i<NODE_ORDER-1; i++) {
					if ((node->entry[i].key == 0) || (key < node->entry[i].key)) {
						insertion_idx = i;
						BPF_DEBUG("key %d must be stored in index %d\n", key, insertion_idx);
						break;
					}
				}
				if(!insertion_idx) {
					BPF_DEBUG("key %d must be stored outside the node.\n", key);
					BPF_DEBUG("temporarily storing the current key\n");
					extra_node_entry.key = key;
					if (left_child == 0) { 
						extra_node_entry.pointer = free_data_index;
					} else {
						extra_node_entry.pointer = left_child;	
					}
				} else {
					BPF_DEBUG("key %d must be stored inside the node.\n", key);
					BPF_DEBUG("temporarily storing the last key already in %d\n", node->entry[NODE_ORDER-2].key);
					extra_node_entry.key = node->entry[NODE_ORDER-2].key;
					if (right_child==0) {
						extra_node_entry.pointer = node->entry[NODE_ORDER-2].pointer;
					} else {
						extra_node_entry.pointer = right_child;
					}

					BPF_DEBUG("readjusting the node before inserting the new key in index %d ...\n", insertion_idx);
					for (i=NODE_ORDER-2; i >= 0; i--) {
						BPF_DEBUG("pushing forward key %d at index %d\n",  node->entry[i].key, i); 
						node->entry[i+1].key = node->entry[i].key;
						node->entry[i+1].pointer = node->entry[i].pointer;
						if (i == insertion_idx) {
							BPF_DEBUG("insertion index %d reached. break\n", i);
							break;
						}
					}
					node->entry[insertion_idx].key = key;
					if (left_child == 0) {
						node->entry[insertion_idx].pointer = free_data_index;
					} else {
						node->entry[insertion_idx].pointer = left_child;
					}
				}
	 

				//TODO split!!
				free_idx = bpf_map_lookup_elem(&free_index_list, &info->free_indexes_tail);
				if (!free_idx) {
					BPF_DEBUG("free index error. return\n");
					return 0;
				}
				BPF_DEBUG("free node index %d\n", *free_idx);

				free_node = bpf_map_lookup_elem(&index_map, free_idx); 
				if (!free_node) {
					BPF_DEBUG("free node error. return\n");
					return 0;
				}

				new_node_idx = *free_idx;
				info->free_indexes_tail--;
				*free_idx = 0;

				__u32 median_idx = NODE_ORDER / 2;
				BPF_DEBUG("median node has index %d\n", median_idx);

				BPF_DEBUG("pushing 2nd nod half to the new node	\n");
				int j=0;
				for (i=median_idx, j=0; i<NODE_ORDER-1; i++, j++) {
					BPF_DEBUG("pushing key idx %d value %d to the new node index %d\n", i, node->entry[i].key, j);
					free_node->entry[j].key = node->entry[i].key;
					free_node->entry[j].pointer = node->entry[i].pointer;	
					node->entry[i].key = 0;
					node->entry[i].pointer=0;
				}

				BPF_DEBUG("pushing extra key %d to the new node index %d\n", extra_node_entry.key, j);
				free_node->entry[j].key = extra_node_entry.key;
				free_node->entry[j].pointer = extra_node_entry.pointer;
				free_node->entry[NODE_ORDER-1].key = j+1;
				node->entry[NODE_ORDER-1].key = num_of_keys_in_node - j;
				node->entry[NODE_ORDER-1].pointer = *free_idx;

				if ((insertion_idx == 0) && (right_child))  {  
					//the insert key was temporarily stored outside the node
					free_node->entry[j+1].pointer = right_child;
				}
				nodes_traversed_count --;
				key = free_node->entry[0].key; //the median that has to be inserted in the parent
				left_child = node_index;
				right_child = new_node_idx; 

				if (nodes_traversed_count == 0) {
					need_a_new_root = 1;
					break;
				}
			} else {
				//
				BPF_DEBUG("the node is not full. There are %d keys. ORDERED INSERTION!\n", num_of_keys_in_node);
				
				BPF_DEBUG("finding the index where the new key should be stored\n");
				for (i=0; i<NODE_ORDER; i++) {
					if ((node->entry[i].key == 0) || (key < node->entry[i].key)) {
						insertion_idx = i;
						BPF_DEBUG("key %d must be stored in index %d\n", key, insertion_idx);
						break;
					}
				}

				if (insertion_idx == num_of_keys_in_node) {
					BPF_DEBUG("there are no other keys to be pushed forward\n");
					node->entry[insertion_idx].key = key;

					if (left_child == 0) {
						node->entry[insertion_idx].pointer = free_data_index;
					} else {
						node->entry[insertion_idx].pointer = left_child;
					}

					node->entry[NODE_ORDER-1].key ++;
					
					if (right_child) {
						BPF_DEBUG("update right child. num of keys %d, right child %d\n", num_of_keys_in_node, right_child);
						if (insertion_idx +1 < NODE_ORDER-1) {
							node->entry[insertion_idx+1].pointer = right_child;
						}
					}
				 } else {	

					BPF_DEBUG("readjusting the node before inserting the new key ...\n");
					for (i=NODE_ORDER-3; i >= 0; i--) {
						if (node->entry[i].key == 0) {
							BPF_DEBUG("entry %d empty\n", i);
							continue;
						}
						node->entry[i+1].key = node->entry[i].key;
						node->entry[i+1].pointer = node->entry[i].pointer;
						if (i == insertion_idx) {
							BPF_DEBUG("insertion index reached %d. break\n", i);
							break;
						}
					} 

					node->entry[insertion_idx].key = key;
					if (left_child == 0) {
						node->entry[insertion_idx].pointer = free_data_index;
					} else {
						node->entry[insertion_idx].pointer = left_child;
					}
					if ((right_child) &&  (insertion_idx+1 < NODE_ORDER)) {
						node->entry[insertion_idx+1].pointer = right_child;
					}
					node->entry[NODE_ORDER-1].key ++;		
				}
				//we have reached a non-full node. break the recursion loop
				break;
			}
		}

		if (need_a_new_root) {
			BPF_DEBUG("we are in the root node. we need a new root\n");
			BPF_DEBUG("key %d, left %d right %d\n", key, left_child, right_child);

			struct bplus_node * new_root_node = NULL;

			free_idx = bpf_map_lookup_elem(&free_index_list, &info->free_indexes_tail);
			if (!free_idx) {
				BPF_DEBUG("free index error. return\n");
				return 0;
			}
			BPF_DEBUG("free node index %d\n", *free_idx);

			new_root_node = bpf_map_lookup_elem(&index_map, free_idx);
			if (!new_root_node) {
				BPF_DEBUG("free node error. return\n");
				return 0;
			}

			info->free_indexes_tail--;
			info->curr_root = *free_idx;
			*free_idx = 0;

			info->curr_h++;

			new_root_node->entry[0].key = key; 
			new_root_node->entry[0].pointer = left_child;  //left child
			new_root_node->entry[1].pointer = right_child;   //right child
			new_root_node->entry[NODE_ORDER-1].key = 1;
		}

		return free_data_index;	
	} else if (cmd == OP_DELETE) {
		BPF_DEBUG("DELETE cmd received\n");
		//index == leaf node index
		return 0;
	} else {
		BPF_DEBUG("unrecognized command. nothing to do ...\n");
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

			BPF_DEBUG("received command %d key %d\n", p->cmd, p->key);
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
