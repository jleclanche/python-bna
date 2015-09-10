Using the command-line tool
===========================

bna is a command line interface to the python-bna library. It can store and manage multiple authenticators, as well as create new ones.


Two things to remember:
 - Using an authenticator on the same computer as the one you're playing on is *not secure*.
 - It is impossible (without knowing the secret) to import an existing authenticator

Configuration is stored in ~/.config/bna/bna.conf. You can pass a different config directory with --config=~/.bna.conf for example.

Creating a new authenticator
----------------------------
::

	$ bna --new

If you do not already have an authenticator, it will be set as default. You can pass --set-default otherwise.

Getting an authentication token
-------------------------------
::

	$ bna
	01234567
	$ bna EU-1234-1234-1234
	76543210

Getting a serial's restore code
-------------------------------
::

	$ bna --restore-code
	Z45Q9CVXRR
	$ bna --restore EU-1234-1234-1234 ABCDE98765
	Restored serial EU-1234-1234-1234

Using the python-bna library
============================

Requesting a new authenticator
------------------------------
::

	import bna
	try:
		# region is EU or US
		# note that EU authenticators are valid in the US, and vice versa
		serial, secret = bna.request_new_serial("US")
	except bna.HTTPError as e:
		print("Could not connect:", e)

Getting a token
---------------
::

	# Get and print a token
	token, time_remaining = bna.get_token(secret=secret)
	print(token)

	# print a new token every time the previous one expires
	from time import sleep
	while True:
		token, time_remaining = bna.get_token(secret=secret)
		print(token)
		sleep(time_remaining)
