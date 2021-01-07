# python-bna

## Requirements

- Python 3.6+


## Command-line usage

bna is a command line interface to the python-bna library. It can store
and manage multiple authenticators, as well as create new ones.


Remember: Using an authenticator on the same device as the one you log in with
is less secure than keeping the devices separate. Use this at your own risk.

Configuration is stored in `~/.config/bna/bna.conf`. You can pass a
different config path with `bna --config=~/.bna.conf` for example.


### Creating a new authenticator

    $ bna new

If you do not already have an authenticator, it will be set as default.
You can pass `--set-default` otherwise.


### Getting an authentication token

    $ bna
    01234567
    $ bna EU-1234-1234-1234
    76543210


### Getting an authenticator's restore code

    $ bna show-restore-code
    Z45Q9CVXRR
    $ bna restore EU-1234-1234-1234 ABCDE98765
    Restored EU-1234-1234-1234


### Getting an OTPAuth URL

To display the OTPAuth URL (used for setup QR Codes):

    $ bna show-url
    otpauth://totp/Blizzard:EU123412341234:?secret=ASFAS75ASDF75889G9AD7S69AS7697AS&issuer=Blizzard&digits=8

Now paste this to your OTP app, or convert to QRCode and scan, or
manually enter the secret.

This is compatible with standard TOTP clients and password managers such as:
- [andOTP](https://play.google.com/store/apps/details?id=org.shadowice.flocke.andotp) (Android),
- [KeepassXC](https://keepassxc.org/) (Cross-platform)
- [1Password](https://1password.com/) (Cross-platform)


#### Getting a QR code

To encode to a QRCode on your local system install \'qrencode\'

For a PNG file saved to disk :

    $ bna show-url | qrencode -o ~/BNA-qrcode.png
    # Scan QRCode
    $ rm ~/BNA-qrcode.png

Or to attempt ot display QRCode in terminal as text output :

    $ bna --otpauth-url | qrencode -t ANSI


## Python library usage

### Requesting a new authenticator

```py
import bna
try:
    # region is EU or US
    # note that EU authenticators are valid in the US, and vice versa
    serial, secret = bna.request_new_serial("US")
except bna.HTTPError as e:
    print("Could not connect:", e)
```

### Getting a token

```py
    # Get and print a token using PyOTP
    from pyotp import TOTP
    totp = TOTP(secret, digits=8)
    print(totp.now())
```
