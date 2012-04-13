#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
from argparse import ArgumentParser
from binascii import hexlify, unhexlify
try:
	from configparser import ConfigParser
except ImportError:
	from ConfigParser import ConfigParser
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.pardir))
import bna

class Authenticator(object):
	def __init__(self, args):
		arguments = ArgumentParser(prog="bna")
		arguments.add_argument("-u", "--update", action="store_true", dest="update", help="update token every time")
		arguments.add_argument("-n", "--new", action="store_true", dest="new", help="request a new authenticator")
		arguments.add_argument("-r", "--region", type=str, dest="region", default="US", help="desired region for new authenticators")
		arguments.add_argument("--set-default", action="store_true", dest="setdefault", help="set authenticator as default (also works when requesting a new authenticator)")
		arguments.add_argument("serial", nargs="?")
		args = arguments.parse_args(args)

		self.config = ConfigParser()
		self.config.read([os.path.join(self.getConfigDir(), "bna.conf")])

		# Are we requesting a new authenticator?
		if args.new:
			self.queryNewAuthenticator(args)
			exit()

		if not args.serial:
			serial = self.getDefaultSerial()
			if serial is None:
				self.error("You must provide an authenticator serial")
		else:
			serial = args.serial
		serial = bna.normalizeSerial(serial)

		# Are we setting a serial as default?
		if args.setdefault:
			self.setDefaultSerial(serial)

		# Get the secret from the keyring
		self._secret = unhexlify(self.getSecret(serial))
		if self._secret is None: # No such serial
			self.error("%r: No such serial" % (serial))

		# And print the token
		if args.update:
			self.runLive()

		else:
			token, timeRemaining = bna.getToken(secret=self._secret)
			print(token)

	def error(self, txt):
		sys.stderr.write("Error: %s\n" % (txt))
		exit(1)

	def queryNewAuthenticator(self, args):
		try:
			reply = bna.requestNewSerial(args.region)
		except bna.HTTPError as e:
			self.error("Could not connect: %s" % (e))

		serial = bna.normalizeSerial(reply["serial"])
		secret = hexlify(reply["secret"])

		self.setSecret(serial, secret)

		# We set the serial as default if we don't have one set already
		# Otherwise, we check for --set-default
		if args.setdefault or not self.getDefaultSerial():
			self.setDefaultSerial(serial)

		msg = "Success. Your new serial is: %s" % (reply["serial"])
		print(msg)

	def runLive(self):
		from time import sleep
		print("Ctrl-C to exit")
		while 1:
			token, timeRemaining = bna.getToken(secret=self._secret)
			sys.stdout.write("\r%08i" % (token))
			sys.stdout.flush()
			sleep(1)

	def getConfigDir(self):
		"""
		Gets the path to the config directory
		"""
		configdir = "bna"
		if os.name == "posix":
			home = os.environ.get("HOME")
			base = os.environ.get("XDG_CONFIG_HOME", os.path.join(home, ".config"))
			path = os.path.join(base, configdir)
		elif os.name == "nt":
			base = os.environ["APPDATA"]
			path = os.path.join(base, configdir)
		else:
			raise NotImplementedError("Config dir support not implemented for %s platform" % (os.name))

		if not os.path.exists(path):
			os.makedirs(path)
		return path

	def getDefaultSerial(self):
		if not self.config.has_section("bna"):
			return None
		return self.config.get("bna", "default_serial")

	def setDefaultSerial(self, serial):
		if not self.config.has_section("bna"):
			self.config.add_section("bna")
		self.config.set("bna", "default_serial", serial)

		with open(os.path.join(self.getConfigDir(), "bna.conf"), "w") as f:
			self.config.write(f)

	def getSecret(self, serial):
		if not self.config.has_section(serial):
			return None

		secret = self.config.get(serial, "secret")
		return bytearray(secret, "ascii")

	def setSecret(self, serial, secret):
		if not self.config.has_section(serial):
			self.config.add_section(serial)
		self.config.set(serial, "secret", secret)

		with open(os.path.join(self.getConfigDir(), "bna.conf"), "w") as f:
			self.config.write(f)

def main():
	import signal
	signal.signal(signal.SIGINT, signal.SIG_DFL)
	authenticator = Authenticator(sys.argv[1:])

if __name__ == "__main__":
	main()
