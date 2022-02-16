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

