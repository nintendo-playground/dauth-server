
import secrets

env = {
	"COMPOSE_PROJECT_NAME": input("Project name: "),
	"DAUTH_ISS": input("Issuer (dauth): "),
	"DAUTH_JKU": input("JKU (dauth): "),
	"DAUTH_PORT": input("Port (dauth): "),
	"DCERT_PORT": input("Port (dcert): "),
	"DADMIN_PORT": input("Port (dadmin): "),
	"DADMIN_USERNAME": input("Username (dadmin): "),
	"DADMIN_PASSWORD": input("Password (dadmin): "),
	"DEVICE_TYPE": input("Device type (cert): "),
	
	"DADMIN_SECRET_KEY": secrets.token_hex(16),
	"CHALLENGE_KEY": secrets.token_hex(16),
	"CERTIFICATE_KEY": secrets.token_hex(16)
}

env = "".join("%s=%s\n" %(key, value) for key, value in env.items())

with open(".env", "w") as f:
	f.write(env)
