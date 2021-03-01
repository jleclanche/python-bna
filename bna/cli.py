import base64
import os
import sys
from configparser import ConfigParser
from string import hexdigits
from time import sleep
from typing import List

import click
from pyotp import TOTP

import bna


def get_default_config_path() -> str:
	"""
	Returns the default configuration file path
	"""
	configdir = "bna"
	home = os.environ.get("HOME", "")
	if os.name == "posix":
		base = os.environ.get("XDG_CONFIG_HOME", os.path.join(home, ".config"))
		path = os.path.join(base, configdir)
	elif os.name == "nt":
		base = os.environ["APPDATA"]
		path = os.path.join(base, configdir)
	else:
		path = home

	return os.path.join(path, "bna.conf")


def ishex(s: str) -> bool:
	"""
	Returns True if a string contains only hex digits, False otherwise.
	"""
	return "".join(filter(lambda c: c in hexdigits, s)) == s


class AuthenticatorSerial(click.ParamType):
	name = "serial"

	def convert(self, value: str, param, ctx) -> str:
		if not value:
			value = ctx.obj.get_default_serial()
			if not value:
				if not ctx.obj._serials():
					msg = (
						"You do not have any configured authenticators. "
						"Create a new one with 'bna new' or try "
						"'bna --help' for more information"
					)
				else:
					msg = (
						"You do not have a default authenticator set. "
						"You must provide an authenticator serial or set a "
						"default one with 'bna set-default <serial>'."
					)
				ctx.fail(msg)

		serial = bna.normalize_serial(value)
		if not ctx.obj.config.has_section(serial):
			ctx.fail(f"No such authenticator: {serial}")

		return serial


class App:
	def __init__(self, config: str) -> None:
		self.config_file = os.path.expanduser(config) or get_default_config_path()
		config_dir = os.path.abspath(os.path.dirname(self.config_file))
		if not os.path.exists(config_dir):
			os.makedirs(config_dir)

		self.config = ConfigParser()
		try:
			self.config.read([self.config_file])
		except Exception as e:
			click.echo(f"Could not parse config file {self.config_file}: {e}", err=True)
			exit(1)

	def _serials(self) -> List[str]:
		return [x for x in self.config.sections() if x != "bna"]

	def add_serial(self, serial: str, secret: str, set_default: bool) -> None:
		self.set_secret(serial, secret)

		# We set the serial as default if we don't have one set already
		# Otherwise, we check for --set-default
		if set_default or not self.get_default_serial():
			self.set_default_serial(serial)

	def get_default_serial(self) -> str:
		if not self.config.has_option("bna", "default_serial"):
			return ""
		return self.config.get("bna", "default_serial")

	def set_default_serial(self, serial) -> None:
		if not self.config.has_section("bna"):
			self.config.add_section("bna")
		self.config.set("bna", "default_serial", serial)
		self.write_config()

	def write_config(self) -> None:
		try:
			with open(self.config_file, "w") as f:
				self.config.write(f)
		except IOError as e:
			click.echo(f"Could not open {self.config_file} for writing: {e}", err=True)
			exit(1)

	def get_secret(self, serial: str) -> str:
		if not self.config.has_section(serial):
			return ""

		secret = self.config.get(serial, "secret")

		if len(secret) == 40 and ishex(secret):
			# bna <= 4.0.0 saved secrets as hex instead of more standard base32
			sys.stderr.write("Found old format for secret store. Converting.\n")
			# decode old format
			secret_bytes = bytes.fromhex(secret)
			# re-encode in new format
			secret = base64.b32encode(secret_bytes).decode()
			# save to config (in base32)
			self.set_secret(serial, secret)

		return secret

	def set_secret(self, serial: str, secret: str) -> None:
		if not self.config.has_section(serial):
			self.config.add_section(serial)
		self.config.set(serial, "secret", secret)
		self.write_config()


class DefaultShowGroup(click.Group):
	def parse_args(self, ctx: click.Context, args: List[str]):
		if not args:
			args.append("show")
		return super().parse_args(ctx, args)


@click.group(cls=DefaultShowGroup)
@click.option("--config", default="", help="Path to a different config file to use")
@click.version_option(bna.__version__)
@click.pass_context
def main(ctx: click.Context, config: str) -> None:
	ctx.obj = App(config)


@main.command(help="Show the current authenticator code")
@click.argument("serial", type=AuthenticatorSerial(), default="")
@click.option(
	"--interactive/--no-interactive",
	default=False,
	help="interactive mode: updates the token as soon as it expires",
)
@click.pass_context
def show(ctx: click.Context, serial: str, interactive: bool) -> None:
	secret = ctx.obj.get_secret(serial)
	totp = TOTP(secret, digits=8)
	if interactive:
		click.echo("Ctrl-C to exit")
		while True:
			token = totp.now()
			sys.stdout.write("\r" + token)
			sys.stdout.flush()
			sleep(1)
	else:
		click.echo(totp.now())


@main.command(help="Request a new authenticator")
@click.option("--region", default="US", help="Desired region for the new authenticator")
@click.option("--set-default/--no-set-default", default=True)
@click.pass_context
def new(ctx: click.Context, region: str, set_default: bool) -> None:
	try:
		serial, secret = bna.request_new_serial(region)
	except bna.HTTPError as e:
		click.echo(f"Could not connect: {e}", err=True)
		exit(1)

	serial = bna.normalize_serial(serial)
	ctx.obj.add_serial(serial, secret, set_default=set_default)
	click.echo(f"Success! Your new authenticator is: {bna.prettify_serial(serial)}")


@main.command(help="Delete an authenticator from the configuration")
@click.argument("serial", type=AuthenticatorSerial())
@click.pass_context
def delete(ctx: click.Context, serial: str) -> None:
	if not ctx.obj.config.has_section(serial):
		ctx.fail(f"No such serial: {serial}")
	ctx.obj.config.remove_section(serial)

	# If it's the default serial, remove that
	if serial == ctx.obj.get_default_serial():
		ctx.obj.config.remove_option("bna", "default_serial")

	ctx.obj.write_config()
	click.echo(f"Deleted authenticator: {bna.prettify_serial(serial)}")


@main.command(help="Recover an authenticator from its restore code")
@click.argument("serial")
@click.argument("restore_code")
@click.option("--set-default/--no-set-default", default=False)
@click.pass_context
def restore(
	ctx: click.Context, serial: str, restore_code: str, set_default: bool
) -> None:
	if ctx.obj.config.has_option(serial, "secret"):
		ctx.fail(
			"A secret already exists for this serial. "
			f"Try deleting it first with bna delete {serial}"
		)

	serial = bna.normalize_serial(serial)
	try:
		secret = bna.restore(serial, restore_code)
	except ValueError as e:
		ctx.fail(str(e))

	ctx.obj.add_serial(serial, secret, set_default=set_default)
	click.echo(f"Restored {bna.prettify_serial(serial)}")


@main.command(help="List all configured authenticators")
@click.pass_context
def list(ctx) -> None:
	default = ctx.obj.get_default_serial()
	serials = ctx.obj._serials()
	for serial in serials:
		if serial == default:
			click.echo(f"{serial} (default)")
		else:
			click.echo(serial)

	click.echo(f"{len(serials)} authenticators")


@main.command(help="Set an authenticator as the default one to use for commands")
@click.argument("serial", type=AuthenticatorSerial(), default="")
@click.pass_context
def set_default(ctx: click.Context, serial: str) -> None:
	ctx.obj.set_default_serial(serial)
	click.echo(f"{bna.prettify_serial(serial)} is now your default authenticator.")


@main.command("show-restore-code", help="Display an authenticator's restore code")
@click.argument("serial", type=AuthenticatorSerial(), default="")
@click.pass_context
def show_restore_code(ctx: click.Context, serial: str) -> None:
	secret = ctx.obj.get_secret(serial)
	code = bna.get_restore_code(serial, secret)
	click.echo(code)


@main.command("show-url", help="Display an authenticator's OTPAuth URL (for QR codes)")
@click.argument("serial", type=AuthenticatorSerial(), default="")
@click.pass_context
def show_url(ctx: click.Context, serial: str) -> None:
	secret = ctx.obj.get_secret(serial)

	# Only add a newline if stdout is a tty
	newline = sys.stdout.isatty()
	click.echo(bna.get_otpauth_url(serial, secret), nl=newline)


@main.command("show-secret", help="Display an authenticator's secret")
@click.argument("serial", type=AuthenticatorSerial(), default="")
@click.pass_context
def show_secret(ctx: click.Context, serial: str) -> None:
	secret = ctx.obj.get_secret(serial)
	click.echo(secret)


if __name__ == "__main__":
	main()
