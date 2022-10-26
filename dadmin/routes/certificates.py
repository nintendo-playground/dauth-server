
from Crypto.Cipher import AES
from OpenSSL import crypto
from flask import Blueprint, Response, redirect, render_template, request, session

import datetime
import hmac
import io
import json
import os
import random
import secrets
import zipfile


bp = Blueprint("certificates", __name__)


CERTIFICATE_KEY = bytes.fromhex(os.environ["CERTIFICATE_KEY"])


def generate_serial_number(id):
	sn = "XAJ70" + "%08i" %id
	
	odd = [int(sn[i]) for i in [3, 5, 7, 9, 11]]
	even = [int(sn[i]) for i in [4, 6, 8, 10, 12]]
	checksum = (10 - sum(odd) - sum(even) * 3) % 10
	return sn + str(checksum)

def generate_device_id():
	# There are lots of weird patterns in the device id, but I have no
	# idea how it is generated. We generate the device id randomly here,
	# and hope that we don't get any collisions.
	did = "6265" + secrets.token_hex(4)
	did += random.choice(["0", "1", "e", "f"])
	did += random.choice(["0", "2", "4", "6", "8", "a", "c", "e"])
	did += "%02x" %(random.randint(0, 24))
	return did

def allocate_devices(count):
	data = {"next_id": 1}
	if os.path.isfile("instance/admin.json"):
		with open("instance/admin.json") as f:
			data = json.load(f)
	
	next_id = data["next_id"]
	
	count = min(count, 100000000 - next_id)
	data["next_id"] += count
	
	devices = []
	for i in range(count):
		did = generate_device_id()
		sn = generate_serial_number(next_id + i)
		devices.append((did, sn))
	
	with open("instance/admin.json", "w") as f:
		json.dump(data, f)
	return devices

def generate_info(did, sn, dt):
	info = {
		"did": did,
		"sn": sn,
		"pc": "HAC",
		"dt": dt
	}
	
	# This is custom
	payload = json.dumps(info, separators=(",", ":")).encode()
	payload += bytes(256 - len(payload) - 48)
	
	aes = AES.new(CERTIFICATE_KEY, AES.MODE_CBC)
	ciphertext = aes.iv + aes.encrypt(payload)
	signature = hmac.digest(CERTIFICATE_KEY, ciphertext, "sha256")
	return ciphertext + signature

def generate_certificate(ca, cakey, did, sn, dt):
	info = generate_info(did, sn, dt)
	
	key = crypto.PKey()
	key.generate_key(crypto.TYPE_RSA, 2048)
	
	serial = secrets.token_bytes(16)
	now = datetime.datetime.now()
	
	cert = crypto.X509()
	cert.set_version(2)
	cert.set_serial_number(int.from_bytes(serial, "big"))
	
	subject = cert.get_subject()
	subject.countryName = "JP"
	subject.stateOrProvinceName = "Kyoto"
	subject.localityName = "Kyoto"
	subject.organizationName = "Nintendo Co.,Ltd."
	subject.commonName = "%s - %s" %(dt, serial.hex().upper())
	
	cert.set_issuer(ca.get_subject())
	cert.set_notBefore(now.strftime("%Y%m%d%H%M%SZ").encode())
	cert.set_notAfter(b"20491208120000Z")
	cert.set_pubkey(key)
	
	san = b"otherName:2.25;OCTETSTRING:%s" %info.hex().upper().encode()
	cert.add_extensions([	
		crypto.X509Extension(b"basicConstraints", True, b"CA:FALSE"),
		crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
		crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca),
		crypto.X509Extension(b"subjectAltName", False, san)
	])

	cert.sign(cakey, "sha256")
	
	p12 = crypto.PKCS12()
	p12.set_certificate(cert)
	p12.set_privatekey(key)
	return p12.export()

def generate_certificates(count, dt, ca, cakey):
	mem = io.BytesIO()
	file = zipfile.ZipFile(mem, "w", zipfile.ZIP_DEFLATED)
	for did, sn in allocate_devices(count):
		file.writestr(sn + ".p12", generate_certificate(ca, cakey, did, sn, dt))
	file.close()
	return mem.getvalue()


@bp.route("/certs", methods=["GET", "POST"])
def certificates():
	if "admin" not in session: return redirect("/login")
	
	if request.method == "POST":
		count = min(max(int(request.form["count"]), 0), 1000)
		dt = request.form["dt"]
		ca = crypto.load_certificate(crypto.FILETYPE_PEM, request.files["ca"].read())
		cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, request.files["cakey"].read())
		
		data = generate_certificates(count, dt, ca, cakey)
		response = Response(data, mimetype="application/zip")
		response.headers.set("Content-Disposition", "attachment", filename="certificates.zip")
		return response
	
	return render_template("certificates.html")
