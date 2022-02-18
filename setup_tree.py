#setup tree info
#bpftool map update name tree_info key hex 00 00 00 00 value hex 00 00 00 00 00 00 00 00 65

import sys
import subprocess
import os
import time

def xdp_load_prog(prog, iface):
    command = [prog, '-d', iface, '-A', '--force']
    out = subprocess.Popen(" ".join(command), shell=True)
    res = out.communicate()

def xdp_raw_map_update(map_name, key, value):
    command = ["bpftool", "map", "update", "name", map_name, "key", "hex", key, "value", "hex", value]
    out = subprocess.Popen(" ".join(command), shell=True)
    res = out.communicate()

def xdp_clear_all(iface):
    command = ["ip l set dev {} xdp off".format(iface)]
    subprocess.Popen(command, shell=True)
    command = ['rm', "/sys/fs/bpf/{}/*".format(iface)]
    os.system(" ".join(command))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("syntax: python3 setup_tree.py <iface> <prog>")
        exit()

    iface = sys.argv[1]
    prog = sys.argv[2]


    print("cleaning XDP..")
    try:
        xdp_clear_all(iface)
    except:
        pass
            
    time.sleep(1)
    print("loading XDP prog ...")
    xdp_load_prog(prog, iface)

    time.sleep(1)
    #setup tree info
    curr_root = "01 00 00 00"
    curr_height = "01 00 00 00"
    #free_indexes_tail = "ff fe 00 00"
    free_indexes_tail = "07 00 00 00"
    is_full = "00 00 00 00"

    value = " ".join([curr_root, curr_height, free_indexes_tail, is_full])
    key = "00 00 00 00"
    xdp_raw_map_update("tree_info", key, value)

    print("loading free idx... it may take a long time...")
    free_idx = []
    for i in reversed(range(2, 10)):
        a = i.to_bytes(4, "little")
        stri = ""
        for j in range(4):
            stri += "{:02x} ".format(i.to_bytes(4, "little")[j])

        free_idx.append(stri)
    
    for i in range(0, 10-2):
        a = i.to_bytes(4, "little")
        stri = ""
        for j in range(4):
            stri += "{:02x} ".format(i.to_bytes(4, "little")[j])
   
        #print(stri, free_idx[i])
        xdp_raw_map_update("free_index_list", stri, free_idx[i])

    exit()

