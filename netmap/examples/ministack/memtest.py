import sys
import os
import commands
import string


for m in (1, 64, 128, 256, 512):
#for m in (1,):
	for n in (1, 64, 128, 256, 512):
#	for n in (64,):
		for pktsiz in (60, 252, 508, 1020):
#		for pktsiz in (60,):
			cmd = "./pkt-gen-prot -w 4 -i %s -f tx -n %d -M 2 -l %d -X %d -m %d"%(sys.argv[1], max(80000000, int(400000000 * float(60)/pktsiz)), pktsiz, n, m)
			os.system(cmd);
			cmd += " -V"
			os.system(cmd);
