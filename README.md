# MAC-Address-Harvester
Python Script to Sniff Mac Addresses from captured Wifi Packets and Graph them in a Pie Chart by Vendor

## Installation
```
git clone git@github.com:gurustave/MAC-Address-Harvester.git
cd MAC-Address-Harvester/
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Execution
```
source venv/bin/activate
sudo airmon-ng start <interface>
sudo python macharvester.py [OPTIONS]
sudo airmon-ng stop <interface>
```

## OPTIONS
```
usage: macharvester.py [-h] [-V VENDOR_FILE] [-I IMPORT_FILE]
                       [-E EXCLUDE_FILE] [-O OUTPUT_FILE | -q] [-g]
                       (-d | -i INTERFACE)

Script utilizing Scapy and MatPlotLib to Harvest MAC Addresses from packets
via a Wireless NIC in Monitor Mode

optional arguments:
  -h, --help            show this help message and exit
  -V VENDOR_FILE, --vendors VENDOR_FILE
                        Specify file for MAC Vendors list. Format: ######
                        Vendor. Defaults to mac_vendors.txt
  -I IMPORT_FILE, --import IMPORT_FILE
                        Specify file of MAC Addresses to import to Harvested
                        list. Format: ##:##:##:##:##:## Vendor
  -E EXCLUDE_FILE, --exclude EXCLUDE_FILE
                        Specify file of MAC Addresses to exclude from
                        Harvested list. Format: ##:##:##:##:##:## Vendor
  -O OUTPUT_FILE, --output OUTPUT_FILE
                        Specify file to output harvested MAC Addresses.
                        Defaults to stdout
  -q, --quiet           Do not output harvested MAC Addresses
  -g, --graph           Display graph of Vendors by percentage of Harvested
                        MAC Addresses. Default False
  -d, --disable         Disable Scanning
  -i INTERFACE, --interface INTERFACE
                        Wireless Interface to scan with (Assumed to already be
                        in Monitor Mode)
```
