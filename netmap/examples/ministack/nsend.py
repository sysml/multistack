import sys
import os
import commands
import string
import time

#
# e.g., python nsend.py [N] [C] [R] [ifname 1] [ifname 2] ...
#
# If it is a receiver, we run each process to monitor all the rings,
# using "R" rings (threads).  Process monitors packets at different ports.
# "C" is set to zero to specify it is the receiver.
#
# If it is the sender, we run each process to send the packets using "C" TCP
# connections.  Each process has "R" threads.  Therefore,  each thread is in
# charge of C/R TCP connections.
# "M" is an indicator whether send packets atop MiniStack (0 is given to send
# directly on netmap)
#

PKT_CMD_ALL = 0x00000001
PKT_CMD_PRE = 0x00000002
PKT_CMD_NOTCPCSUM = 0x0000020

lim = int(sys.argv[1])
if lim > 1024:
	print "the number of processes must be less than 1025"
nconn = int(sys.argv[2])
nthreads = int(sys.argv[3])
nrings = int(sys.argv[4])

sif_cur = 5
sif_num = len(sys.argv) - sif_cur # total - num. processes
sif_end = sif_cur + sif_num

sender_port = 50000
sp_intval = 1
receiver_port = 10510
rp_intval = sp_intval = 1
sender_addr = "10.0.0.2"
receiver_addr = "10.0.0.3"
#npkts = 200111222/(pktsiz/60)
method = PKT_CMD_ALL
npktbufs = 1
#pkt_sizes = (60, 124, 252, 508, 1020)
pkt_sizes = (60, 64, 124, 128, 252, 256, 508, 512, 1020, 1024)

def kill_all(cmd):
	com = "ps auxw | grep " + cmd + " | grep -v grep | grep -v PID | grep -v 'sh -c' | awk '{print $2}'"
	print "Debug ", com
	stat, result = commands.getstatusoutput(com)
	pids = result.split('\n')
	for i in range(0, len(pids)):
		if pids[i] == '':
			break
		com = "kill " + pids[i]
		print "Debug: ", com
		os.system(com)

receiver = True
if (nconn):
	receiver = False
	print "sender"

for p in pkt_sizes:
	npkts = max(400111222/(p/60), 400111222/(252/60))
	count = 5
	while count > 0:
		count -= 1
		for n in range(0, lim):
			cmd = "./pkt-gen-prot -w 4 -T 4000 -i "
			sif = sys.argv[sif_cur]

			if receiver is True:
				cmd += "valeu:%d -h %s -s %s -Y %s -x tcp -u -f rx"%\
					(n, sif, receiver_addr, receiver_port)
				cmd += " -H %d -p %d"%(nrings, nthreads)
				receiver_port += rp_intval
			else:
				cmd += "valeu:%d -h %s -s %s -Y %d -d %s -y %d -f tx -n %d -x tcp -u -M 0x%08x -N %d -H %d -p %d -m %d -l %d"%\
				(n, sif, sender_addr, sender_port, receiver_addr, \
				 receiver_port, npkts, method, max(1,nconn/nthreads), \
				 nrings, nthreads, npktbufs, p)
				if nthreads > 1:
					cmd += " -Q %d -q %d"%(1, nthreads)
				sender_port += sp_intval
# add following to distribute packets to different receivers
#		receiver_port += rp_intval * nthreads
			if (n < lim - 1):
				cmd += " &"
			sif_cur += 1
			if (sif_cur >= sif_end):
				sif_cur = sif_end - sif_num
#	print cmd
			os.system(cmd)
		if receiver is False:
			time.sleep(20)
		else:
			time.sleep(8)
		kill_all('pkt-gen-prot')
		time.sleep(2)
print "finish"
