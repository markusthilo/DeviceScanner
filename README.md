# DeviceScanner
Python tools to scan for Bluetooth and Wifi

## btscan
The command line classic Bluetooth and Bluetooth LE scanner with text, Json and XML output.

### Usage:

sudo python btscan.py

or as root:

python btscan.py

You might want to use manuf.txt from Wireshark on gitlab to link MAC addresses and manufacturers:

sudo python btscan.py -m manuf.txt

For command line arguments (there aren't much) run:

python btscan.py --help

## esp32scan

First steps experimenting with ESP32 to probably find more BT devices.
