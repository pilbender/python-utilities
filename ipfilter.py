#!/usr/bin/env python
# Filename: ipfilter.py
# Date: 1-24-2018
# Author: Richard Scott Smith

# Python rewrite of an old perl utility I wrote back in 2006
# It gives a summary of the IP address occurrence in files.
# Good for examining logs for script kiddie attacks on servers.

import re
import fileinput
from collections import defaultdict

# The keys in the hash tables are by ip address
# Hash table to store the number of times an ip address has occurred
iptable = defaultdict(int)

# Temporary variable to hold the current ip address
ipaddress = ""

# Count up the total number of IP addresses that have been processed
totalNumberOfIPAddresses = 0

# Identify if a line has an IP address on it
def identifyIpAddress(currentIpAddress) :
    global totalNumberOfIPAddresses
    global ipaddress
    pattern = re.compile('\d+\.\d+\.\d+\.\d+')
    match = pattern.search(currentIpAddress)
    if (match):
        totalNumberOfIPAddresses += 1
        ipaddress = match.group()
        #print "Here's an IP: " + ipaddress
        return 1
    else:
        return 0
    # End if-else
# End identifyIPAddress

# Read in all the files, line by line
for line in fileinput.input():
    if (identifyIpAddress(line)):
        if ipaddress in iptable:
            iptable[ipaddress] += 1
        else:
            iptable[ipaddress] = 1


# Finally print the contents of the iptable
print "IP Table:"
for ipaddress in sorted(iptable, key=iptable.get, reverse=True):
    spaces = ipaddress
    spaces += " "
    for i in xrange(len(ipaddress), 20):
        spaces += "-"
    print spaces, iptable[ipaddress]

print ""
print "Total IP addresses scanned: ", totalNumberOfIPAddresses
