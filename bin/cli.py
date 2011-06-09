#!/usr/bin/env python
# -*- coding: utf-8 -*-

import keyring
import os
import sys
from binascii import hexlify, unhexlify
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.pardir))
import bna

SERVICE = "trogdor"

def ERROR(txt):
	sys.stderr.write("Error: %s\n" % (txt))
	exit(1)


def normalizeSerial(serial):
	return serial.lower().replace("-", "").strip()

def prettifySerial(serial):
	serial = normalizeSerial(serial)
	if len(serial) != 14:
		raise ValueError("serial %r should be 14 characters long" % (serial))
	
	def digits(chars):
		if not chars.isdigit():
			raise ValueError("bad serial %r" % (serial))
		return "%04i" % int((chars))
	
	return "%s-%s-%s-%s" % (serial[0:2].upper(), digits(serial[2:6]), digits(serial[6:10]), digits(serial[10:14]))


def getDefaultSerial():
	return "us100604693849" # XXX

def setDefaultSerial(serial):
	pass # TODO


def runAuthenticatorQuery(args):
	try:
		authenticator = bna.requestNewSerial(args.region)
	except bna.HTTPError as e:
		ERROR("Could not connect: %s" % (e))
	
	serial = normalizeSerial(authenticator["serial"])
	secret = hexlify(authenticator["secret"])
	
	keyring.set_password(SERVICE, serial, secret)
	
	# We set the authenticator as default if we don't have one set already
	# Otherwise, we check for --set-default
	if args.setdefault or not getDefaultSerial():
		setDefaultSerial(serial)
	
	print(authenticator["serial"])

def runLive(secret):
	from time import sleep
	print("Ctrl-C to exit")
	while 1:
		token, timeRemaining = bna.getToken(secret=unhexlify(secret))
		sys.stdout.write("\r%08i" % (token))
		sys.stdout.flush()
		sleep(1)


def main():
	import signal
	from optparse import OptionParser
	
	signal.signal(signal.SIGINT, signal.SIG_DFL)
	options = OptionParser()
	options.add_option("-u", "--update", action="store_true", dest="update", help="update token every time")
	options.add_option("-n", "--new", action="store_true", dest="new", help="request a new authenticator")
	options.add_option("-r", "--region", type="string", dest="region", default="US", help="desired region for new authenticators")
	options.add_option("--set-default", action="store_true", dest="setdefault", help="set authenticator as default (also works when requesting a new authenticator)")
	args, serial = options.parse_args(sys.argv[1:])
	
	# Are we requesting a new authenticator?
	if args.new:
		runAuthenticatorQuery(args)
		exit()
	
	# If not, we need a serial
	
	if not serial:
		serial = getDefaultSerial()
		if serial is None:
			ERROR("You must provide an authenticator serial")
	else:
		serial = serial[0]
	serial = normalizeSerial(serial)
	
	# Are we setting a serial as default?
	if args.setdefault:
		setDefaultSerial(serial)
	
	# Get the secret from the keyring
	secret = keyring.get_password(SERVICE, serial)
	if secret is None: # No such serial
		ERROR("%r: No such serial" % (serial))
	
	# And print the token
	if args.update:
		runLive(secret)
	
	else:
		token, timeRemaining = bna.getToken(secret=unhexlify(secret))
		print(token)

if __name__ == "__main__":
	main()
