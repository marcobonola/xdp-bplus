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


#define INDEX_MAP_SIZE	 	1024
#define DATA_MAP_SIZE	 	1024
#define TREE_HEIGTH		3	
#define NODE_SIZE		5

struct index_map_val {
	 __u32 key;
	 __u32 pointer;
};

struct bpf_map_def SEC("maps") index_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct index_map_val),
	.max_entries = INDEX_MAP_SIZE,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps") data_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries =DATA_MAP_SIZE,
	.map_flags = 0,
};

struct payload {
	__u32 key;
};

static inline void * __bplus_search(__u32 search_key) {
	int i, j;
	__u32 index = 0;
	__u32 *data = NULL;
	struct index_map_val * val0 = NULL;
	struct index_map_val * val1 = NULL;
	int found = 0;


	for (i=0; i<TREE_HEIGTH; i++) {
    		val0 = bpf_map_lookup_elem(&index_map, &index);
		if (val0 == NULL) {
			return NULL;
		}
		for (j=0; j<NODE_SIZE-1; j++) {
			//for now, just for simplicity, we use linear search
			//TODO do a binary search
			if (i != TREE_HEIGTH -1) { //we are in the root or in an intermediate node
				bpf_printk("NON LEAF i %d j %d\n",i, j );
				bpf_printk("comparing %d with %d\n", search_key, val0->key);
				if (search_key < val0->key) {
					bpf_printk("LESS\n");
					index = val0->pointer; 	
					bpf_printk("index = %d\n", val0->pointer);
					break;
				} else {
					index ++;
					val1 = bpf_map_lookup_elem(&index_map, &index);
					if (val1 == NULL) {
						return NULL;
					}
					if ((search_key == val0->key) || (val1->key == 0) ) {
						bpf_printk("EQUAL or NEXT 0\n");
						index = val1->pointer;
						bpf_printk("index = %d\n", val1->pointer);
						break;
					} else { //i need the next element
						bpf_printk("GREATER\n");
						if (j == NODE_SIZE - 2) { //last element
							index = val1->pointer;
							bpf_printk("LAST element index = %d\n", val1->pointer);
							break;
						} else {
							val0 = val1; 
						}
					}
				}
			} else { //we are in a leaf node
				bpf_printk("LEAF i %d j %d\n",i, j );
				bpf_printk("search key %d cur key %d\n", search_key, val0->key);
				if (search_key == val0->key) {
					index = val0->pointer;		
					found = 1; //we can spare this variable if we don't use data index 0
					bpf_printk("LEAF NODE found index %d\n", index);
					break;
				} else {
					index ++;
					val0 = bpf_map_lookup_elem(&index_map, &index);
					if (val0 == NULL) {
						return NULL;
					}
				}
			}
		}

	}
	
	if (!found) {
		bpf_printk("not found\n");
	} else {
		data = bpf_map_lookup_elem(&data_map, &index);
		if (data) {
			return data;
		}
	} 
	
	return NULL;
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
	__u32 *val = NULL;
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

			val = __bplus_search(p->key);
		}

		__builtin_memcpy(eth->h_dest, h_source, 6);
		__builtin_memcpy(eth->h_source, h_dest, 6);
		ip->saddr = daddr;
		ip->daddr = saddr;
		udp->source = dport;
		udp->dest = sport;

		

		if (!val) { 
			__u32 tmp = 0;
			__builtin_memcpy(p, &tmp, 4);
		} else {
			__builtin_memcpy(p, val, 4);
		}

		return XDP_TX;

	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
