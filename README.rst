Using the command-line tool
===========================

bna is a command line interface to the python-bna library. It can store and manage multiple authenticators, as well as create new ones.


Two things to remember:
 - Using an authenticator on the same computer as the one you're playing on is *not secure*.
 - It is impossible (without knowing the secret) to import an existing authenticator

Creating a new authenticator
----------------------------
::

	$ bna --new --set-default

Getting an authentication token
-------------------------------
::

	$ bna
	01234567

Using the python-bna library
============================

Requesting a new authenticator
------------------------------
::

	import bna
	try:
		# region is EU or US
		# note that EU authenticators are valid in the US, and vice versa
		authenticator = bna.requestNewSerial("US")
		secret = authenticator["secret"]
		serial = authenticator["serial"]
	except bna.HTTPError, e:
		print "Could not connect:", e

Getting a token
---------------
::

	# Get and print a token
	token, timeRemaining = bna.getToken(secret=secret)
	print token

	# print a new token every time the previous one expires
	from time import sleep
	while True:
		token, timeRemaining = bna.getToken(secret=secret)
		print token
		sleep(timeRemaining)
