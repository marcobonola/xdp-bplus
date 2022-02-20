import subprocess
import graphviz
from graphviz import nohtml
import math

NODE_ORDER = 4

g = graphviz.Digraph('g', filename='btree.gv', node_attr={'shape': 'record', 'height': '.1'})


def reverse_order(val):
  little_hex = bytearray.fromhex(val)
  little_hex.reverse()
  str_little = ''.join(format(x, '02x') for x in little_hex)
  return str_little


if __name__ == "__main__":
    #print("getting root node idx ...")    
    #output = str(subprocess.check_output(['sudo', 'bpftool', 'map', 'dump', 'name', 'tree_info']))
    #value_byte_list = output.split("\\n")[0].split("value:")[1].split()

    #hex_values = []
    #for i in range(4):
    #    tmp = value_byte_list[i+0] + value_byte_list[i+1] + value_byte_list[i+2] + value_byte_list[i+3]
    #    hex_values.append(tmp)

    #root_idx = int(reverse_order(hex_values[0]),16)
    #print("the root idx is: {}".format(root_idx))

    print("parsing the index map...")
    output = str(subprocess.check_output(['sudo', 'bpftool', 'map', 'dump', 'name', 'index_map']))

    splitted  = output.split("Found")[0].split("key:")
    splitted.pop(0)

    nodes_hex_values = []
    for i in range(len(splitted)):
        tmp = splitted[i].split("value:")[1].replace("\\n"," ").split() 
        nodes_hex_values.append(tmp)

    nodes  = []

    for node_to_be_parsed in nodes_hex_values:
        tmp_node = []
        for k in range(NODE_ORDER*2):
            tmp = node_to_be_parsed[4*k+0] + node_to_be_parsed[4*k+1] + node_to_be_parsed[4*k+2] + node_to_be_parsed[4*k+3]

            tmp_node.append(tmp)

        if tmp_node[NODE_ORDER*2-1] != "00000000": 
            nodes.append(tmp_node)

    #convert hex to int
    nodes_int  = []
    for node in nodes:
        node = [int(reverse_order(k),16) for k in node]
        nodes_int.append(node)

    print(nodes_int)

    #create node objects
    node_idx = 1
    for node in nodes_int:
        name = "node-{}".format(node_idx)
        entries = ""

        fields_string = ""
        for i in range(NODE_ORDER*2-1):
            field = "<f{}>{}"
            if (i % 2) == 0: #is odd
                label = "" 
            else:
                label = node[i] if node[i]!=0 else "" 

            fields_string += field.format(i, label)
            if i < NODE_ORDER*2 - 2:
                fields_string += "|"
        
        g.node(name, nohtml(fields_string))
        node_idx += 1


    #create edges
    node_idx = 1
    for node in nodes_int:
        src = "node-{}:f{}"
        dst = "node-{}:f{}"
        for i in range(NODE_ORDER):
            edge_str = ""
            print("node {}, src field {}, dst {}".format(node_idx, i*2, node[i*2]))
            if node[i*2] not in [0,1234]:
                g.edge(src.format(node_idx, i*2), dst.format(node[i*2], NODE_ORDER)) 


        node_idx += 1
    
    g.view()
    

    
