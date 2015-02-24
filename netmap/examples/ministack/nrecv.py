import sys
import os
import time

n = int(sys.argv[1])
for i in range(n):
	cmd = './pkt-gen-prot -w 4 -T 4000 -i %s -f rx'%(sys.argv[2])
	os.system(cmd)
	time.sleep(3)
