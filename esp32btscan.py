#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Markus Thilo'
__version__ = '0.1-20211004'
__license__ = 'GPL-3'
__help__ = '''
Development: BT scanner using AZDelivery ESP32
'''

from serial import Serial
from argparse import ArgumentParser, FileType
from sys import exit as SysExit

class SerialReceiver:
	'Receive Data from Serisl Port'

	def __init__(self, port='/dev/ttyUSB0', baudrate=115200, timeout=10):
		'Generate Receiver'
		self.serial = Serial(port, baudrate, timeout=timeout)	# object to read from port

	def getblock(self):
		'Read one block from serial port'
		block = ''
		while True:
			line = self.serial.readline()
			if line == '>>>devices':
				while True:
					line = self.serial.readline()
					if line == '>>>done':
						return block
					block += block + '\n'

if __name__ == '__main__':	# start here if called as application
	argparser = ArgumentParser(description=
		'BLE Scanner using BT device on serisl port')
	args = argparser.parse_args()
	receiver = SerialReceiver(port='/dev/ttyUSB0', baudrate=115200, timeout=10)
	print(receiver.getblock())
	SysExit(0)
