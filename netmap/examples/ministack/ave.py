import sys
import re
import glob

#
# main
#

f = open(sys.argv[1])
num = int(sys.argv[2])
total = 0
i = 0
for line in f.readlines():
	total += float(line.strip())
	i += 1
	if i == num:
		print total/5
		i = 0
