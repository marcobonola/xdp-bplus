# Environment Setup
0. recomended environment: Linux \*ubuntu 18.04 VM 

1. clone the xdp-tutorial repo
	```
	git clone https://github.com/xdp-project/xdp-tutorial.git
	```

2. setup xdp-tutorial (do as reported in `setup_dependencies.org`)

3. verify the xdp-tutorial setup my compiling the project (`make` from the root dir)

4. move the xdp-bplus dir into xdp-tutorial

5. modify the Makefile in xdp-tutorial/ to build the xdp-blus dir
	1. add the following line to xdp-tutorial/Makefile

		```
		LESSONS += xdp-bplus
		```
		
	2. cd into xdp-bplus and run `make`
	3. you get 2 files: `blpustree.o` (the xdp object) and `bplustree_user` (the loader)

6. in order to test the bplus prototype we need to send packets to the interface into which we load the xdp object. The simplest thing to do is to use the Linux host machine. In anycase, to run the application responsible for generating test packets we need python and scapy

	1. install scapy in the machine used to send packets
		```	
		pip3 install scapy
		```
	2. move the file `bplus_test.py` into the machine that will be used to send packets

# How to test the prototype

0. (in the VM running the xdp program) cd into xdp-bplus
1. load the eBPF program (let's assume ens3 is the device to wihch we load the xdp program)
```
sudo ./bplustree_user -d ens33 -A [--force] 
```

(the last option is required to re-load the program if already attached)

2. configure the eBPF maps 
```
sudo ./setup_indexes.sh
sudo ./setup_data.sh
```

3. (not mandatory) to read the debug messages
```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

4. move to the machine running the python test program (see the reference tree used in the first test in `notes.pdf`)
```
sudo python3 bplus_test.py KEY_TO_FIND
```

5. to unload the xdp program
```
sudo ip link set dev ens33 xdp off
```

