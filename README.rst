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
