#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Markus Thilo'
__version__ = '0.1_2021-05-11'
__license__ = 'GPL-3'

from bluetooth import discover_devices, find_service
from bluepy.btle import Scanner, DefaultDelegate
from datetime import datetime
from json import dumps
from yattag import Doc, indent
from re import match
from argparse import ArgumentParser, FileType
from sys import exit as SysExit

class Manufacturer:
	'Identify device manufacturer using the Wireskark list'

	def __init__(self, manuffile):
		self.__dict__ = dict()	# dictionary to store manufacturers by mac identifier
		if manuffile == None:
			for fname in 'manuf.txt', '$HOME/manuf.txt', '/etc/manuf.txt':	# default paths
				try:
					manuffile = open(fname)
					break
				except FileNotFoundError:
					continue
		if manuffile == None:
			return
		for line in manuffile.readlines():
			s = line.split('\t')	# ...because mac and manufacturer information are tab seperated
			m = match('^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}.*', s[0].lower())	# check for mac
			if m != None:
				mac = m.group().replace(':', '')	# get rid of redundant ':'
				try:	# address range with /28 e.g.
					mac = mac[:round(int(mac.split('/')[1])/4)]
					for i in range(6, len(mac)):	# get rid of larger range
						try:
							self.__dict__.pop(mac[:i])
						except KeyError:
							pass
				except IndexError:
					pass
				if len(s) == 2:	# use only one column
					self.__dict__[mac] = s[1].rstrip('\n')
				else:
					self.__dict__[mac] = s[2].rstrip('\n')
		manuffile.close()

	def get(self, mac):
		'Get manufacturer as string'
		mac = mac.lower().replace(':', '')
		for ident in self.__dict__:
			if mac[:len(ident)] == ident:
				return self.__dict__[ident]
		return 'unknown'

class BluetoothScan:
	'Scanner for detectable Bluetooth Devices (classic BT)'

	def __init__(self, duration=3, manufacturer=Manufacturer(None)):
		'Scan for Devices'
		self.devices = [
			{
				'addr': addr.lower(),
				'name': name,
				'manuf': manufacturer.get(addr),
				'ts': f'{datetime.now()}',
				'services': find_service(address=addr)
			} for addr, name in discover_devices(duration=duration, flush_cache=True, lookup_names=True)
		]

	def __repr__(self):
		'Readable output'
		out = '< BLUETOOTH CLASSIC >\n\ndevice bluetooth address\tdevice name\tmanufacturer\tseen (system time)'
		out += '\n\tservice name\tdescription\tservice provider\tprotocol\tservice host\tport\n'
		for device in self.devices:
			out += f"\n\n{device['addr']}\t{device['name']}\t{device['manuf']}\t{device['ts']}"
			for service in device['services']:
				out += '\n'
				for key in 'name', 'description', 'provider', 'protocol', 'host', 'port':
					if key in service:
						if service[key] != None:
							out += f'\t{service[key]}'
						else:
							out += f'\t{key} undetected'
		return out

class BTLEScan:
	'Scanner for detectable Bluetooth Low Energy Devices'

	class ScanDelegate(DefaultDelegate):
		'Handler for received data'

		def __init__(self, manuf):
			'Generate emty dictionary to store dicovered devices'
			DefaultDelegate.__init__(self)
			self.devices = dict()
			self.manuf = manuf

		def gen_discovery(self, dev):
			'Generate strucured infos on contact'
			return {
				'ts': f'{datetime.now()}',
				'addrType': dev.addrType,
				'rssi': dev.rssi,
				'connectable': dev.connectable,
				'updateCount': dev.updateCount,
				'scanData': dev.getScanData()
			}

		def handleDiscovery(self, dev, isNewDev, isNewData):
			if isNewDev:
				self.devices[dev.addr] = {
					'addr': dev.addr,
					'manuf': self.manuf.get(dev.addr),
					'detections': 1,
					'updates': 1,
					'data': [self.gen_discovery(dev)]
				}
			else:
				self.devices[dev.addr]['detections'] += 1
				if isNewData:
					self.devices[dev.addr]['updates'] += 1
					self.devices[dev.addr]['data'].append(self.gen_discovery(dev))
				else:
					self.devices[dev.addr]['data'].append({'ts': f'{datetime.now()}'})

	def __init__(self, duration=3, manufacturer=Manufacturer(None)):
		'Create Scanner'
		self.delegate = self.ScanDelegate(manufacturer)
		self.scanner = Scanner().withDelegate(self.delegate)
		self.scanner.scan(duration)
		self.devices = [ data for addr, data in self.delegate.devices.items() ]

	def __repr__(self):
		'Readable output'
		out = '< BLUETOOTH LOW ENERGY >\n\ndevice address\tmanufacturer\tdetections / updates'
		out += '\n\tseen (system time)\ttype\tconnectable\trssi\tupdates\t(manufacturer)'
		for device in self.devices:
			out += f"\n\n{device['addr']}\t{device['manuf']}\t{device['detections']} / {device['updates']}"
			for data in device['data']:
				out += f"\n\t{data['ts']}"
				try:
					out += f"\t{data['addrType']}\t"
					if data['connectable']:
						out += 'yes'
					else:
						out += 'no'
					out += f"\t{data['rssi']}\t{data['updateCount']}\t"
					for scandata in data['scanData']:
						if 'Manufacturer' in scandata:
							out += f"{scandata[2]}"
				except KeyError:
					pass
		return out

class XML:
	'Generate XML'

	TAGS = ('device', 'infos', 'infos', 'infos')

	def __init__(self, root, data):
		'Generate parser'
		self.doc, self.tag, self.text = Doc().tagtext()
		self.root = root
		self.data = data

	def __gen__(self, tag, data, depth):
		with self.tag(tag):
			if isinstance(data, list):
				for element in data:
					self.__gen__(self.TAGS[depth], element, depth+1)
			elif isinstance(data, dict):
				for key, item in data.items():
					self.__gen__(key, item, depth)
			elif isinstance(data, tuple):
				for element in data:
					self.__gen__('info', element, depth)
			else:
				self.text(f'{data}')

	def __repr__(self):
		'XML output'
		self.__gen__(self.root, self.data, 0)
		return indent(self.doc.getvalue(), indentation = '  ', newline = '\r\n')

if __name__ == '__main__':	# start here if called as application
	argparser = ArgumentParser(description='Analize netflow data')

	argparser.add_argument('-c', '--classic', action='store_true',
		help='Scan for classic Bluetooth devices only'
	)
	argparser.add_argument('-j', '--json', type=FileType('w'),
		help='Json file to write', metavar='FILE', default=None
	)
	argparser.add_argument('-l', '--le', action='store_true',
		help='Scan for Bluetooth LE devices only'
	)
	argparser.add_argument('-m', '--manuf', type=FileType('r'),
		help='Manufacturer list', metavar='FILE', default=None
	)
	argparser.add_argument('-s', '--scantime', type=float,
		help='Time span for scanning', metavar='SECONDS', default=3
	)
	argparser.add_argument('-w', '--writetxt', type=FileType('w'),
		help='Text file to write', metavar='FILE', default=None
	)
	argparser.add_argument('-x', '--xml', type=FileType('w'),
		help='XML file to write', metavar='FILE', default=None
	)
	args = argparser.parse_args()
	manuf = Manufacturer(args.manuf)
	if not args.le:	# scan classic bluetooth devices
		btdevices = BluetoothScan(duration=args.scantime, manufacturer=manuf)
		print(btdevices)
		if args.writetxt != None:
			print(btdevices, file=args.writetxt)
		if args.xml != None:
			xml = XML('bluetooth', btdevices.devices)
			print(xml, file=args.xml)
	if not args.classic ^ args.le:	# generate empty line inbetween bt classic and btle
		print()
		if args.writetxt != None:
			print(file=args.writetxt)
		if args.xml != None:
			print(file=args.xml)
	if not args.classic:	# scan btle devices
		btledevices = BTLEScan(duration=args.scantime, manufacturer=manuf)
		print(btledevices)
		if args.writetxt != None:
			print(btledevices, file=args.writetxt)
		if args.xml != None:
			xml = XML('btle', btledevices.devices)
			print(xml, file=args.xml)
	if args.json != None:	# generate json file
		json = dict()
		if not args.le:
			json.update({'bluetooth': btdevices.devices})
		if not args.classic:
			json.update({'blle': btledevices.devices})
		print(json, file=args.json)
	SysExit(0)
