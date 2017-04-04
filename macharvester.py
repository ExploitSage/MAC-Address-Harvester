#!/usr/bin/env python2

import sys
import os
import re
import collections
import thread
import argparse

from scapy.all import *
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib import style

def extant_file(x):
    """
    'Type' for argparse - checks that file exists and opens for readonly.
    """
    if not os.path.exists(x):
        # Argparse uses the ArgumentTypeError to give a rejection message like:
        # error: argument input: x does not exist
        raise argparse.ArgumentTypeError("{0} does not exist".format(x))
    return open(x,'r')

def output_file(x):
    """
    'Type' for argparse - Opens file and attaches to stdout.
    """
    sys.stdout = open(x,'w')


parser = argparse.ArgumentParser(description="Script utilizing Scapy and MatPlotLib to Harvest MAC Addresses from packets via a Wireless NIC in Monitor Mode")

parser.add_argument("-V", "--vendors", dest="vendor_file", type=extant_file, default="mac_vendors.txt", action="store", help="Specify file for MAC Vendors list. Format: ###### Vendor. Defaults to mac_vendors.txt")
parser.add_argument("-I", "--import", dest="import_file", type=extant_file, action="store", help="Specify file of MAC Addresses to import to Harvested list. Format: ##:##:##:##:##:## Vendor")
parser.add_argument("-E", "--exclude", dest="exclude_file", type=extant_file, action="store", help="Specify file of MAC Addresses to exclude from Harvested list. Format: ##:##:##:##:##:## Vendor")

output_group = parser.add_mutually_exclusive_group()
output_group.add_argument("-O", "--output", dest="output_file", type=output_file, action="store", help="Specify file to output harvested MAC Addresses. Defaults to stdout")
output_group.add_argument("-q", "--quiet", default=False, action="store_true", help="Do not output harvested MAC Addresses")

parser.add_argument("-g","--graph", default=False, action="store_true", help="Display graph of Vendors by percentage of Harvested MAC Addresses. Default False")

scan_group = parser.add_mutually_exclusive_group(required=True)
scan_group.add_argument("-d", "--disable", default=False, action="store_true", help="Disable Scanning")
scan_group.add_argument("-i", "--interface", dest="interface", action="store", help="Wireless Interface to scan with (Assumed to already be in Monitor Mode)")

args = parser.parse_args()

# Open MAC address Database. Format: ###### Vendor
with args.vendor_file as vendor_file:
    vendor_lines = [vendor.rstrip() for vendor in vendor_file]

found_macs = []
found_vendors = []

excluded_macs = []

style.use('fivethirtyeight')
fig = plt.figure()
ax1 = fig.add_subplot(1,1,1)

def remove_value_from_list(haystack, needle):
    return [value for value in haystack if value != needle]

def update_pie_chart(i):
    # Get Ordered Dictionary of (Vendors, Occurances) sorted by Number of Appearances
    vendors_list = remove_value_from_list(found_vendors,None)
    vendors_count = collections.Counter(vendors_list)
    vendors_sorted = sorted(vendors_count.items(), key=lambda x: x[1])
    vendors = collections.OrderedDict(vendors_sorted)
    #Clear and redraw pie chart
    ax1.clear()
    plt.title('MAC Addresses by Vendor')
    ax1.pie(
        vendors.values(),
        labels=vendors.keys(),
        autopct='%1.1f%%',
        shadow=True,
        startangle=180)

def vendor_lookup(mac):
    vendor_mac=re.compile(re.sub(':','',mac)[0:6],re.IGNORECASE)
    for vendor in vendor_lines:
        if re.search(vendor_mac,vendor):
            return vendor[7:]

def add_mac(mac):
    vendor = vendor_lookup(mac)
    found_macs.append(mac)
    found_vendors.append(vendor)
    if not args.quiet:
        print("%s %s" % (mac, vendor))
        sys.stdout.flush()
        # os.fsync(sys.stdout.fileno())

def PacketHandler(pkt):
    if pkt.addr2 != None and pkt.addr2 not in excluded_macs and pkt.addr2 not in found_macs:
        add_mac(pkt.addr2)

if args.exclude_file != None:
    for mac in args.exclude_file:
        excluded_macs.append(mac.strip().split()[0])

class PseudoPacket:
    def __init__(self, mac):
        self.addr2 = mac

if args.import_file != None:
    for mac in args.import_file:
        PacketHandler(PseudoPacket(mac.strip().split()[0]))

if not args.disable:
    if args.graph:
        # Start Packet Sniffer in separate thread
        thread.start_new_thread(sniff, (), dict(iface=args.interface, prn=PacketHandler))
    else:
        sniff(iface=args.interface, prn=PacketHandler)
if args.graph:
    # Setup Pie Chart, Begin 1s refresh, and show initial graph
    update_pie_chart(0)
    ani = animation.FuncAnimation(fig, update_pie_chart, interval=1000)
    plt.show()
