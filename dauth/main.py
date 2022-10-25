
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from OpenSSL import crypto
from akamai.edgeauth import EdgeAuth
from cachetools import cached, TTLCache
from flask import Flask, request

from common import db

import asn1
import base64
import binascii
import datetime
import hmac
import json
import jwt
import os
import secrets
import struct
import time
import urllib
import uuid


app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)


CHALLENGE_KEY = bytes.fromhex(os.environ["CHALLENGE_KEY"])
CERTIFICATE_KEY = bytes.fromhex(os.environ["CERTIFICATE_KEY"])

MAC_KEY = bytes.fromhex("8be45abcf987021523ca4f5e2300dbf0")

MAC_KEYS = {
	8: bytes.fromhex("b802c58176dcac42bd9e0d2d1d8fac31"),
	9: bytes.fromhex("1c223bb3037e98a07575aef737e69a32"),
	10: bytes.fromhex("204d0fd7cf8f3c7586062158e47d3499"),
	11: bytes.fromhex("5a7122127f71a1297e8330b52b75cca7"),
	12: bytes.fromhex("afd03c400b7bf3e816d3ab0e9b2c564f"),
	13: bytes.fromhex("edbad73432ceea43bb1b9e398e414d03"),
	14: bytes.fromhex("9978ffd6ce3ce28c1ecc69cb611843eb"),
	15: bytes.fromhex("dca8c7c547a954b5e7a605ba7876766f")
}

ALLOWED_KEYS = {
	6: ["8", "9", "10", "11", "12"],
	7: ["11", "12", "13", "14", "15"]
}


class DAuthError:
	OK = 0
	UNAUTHORIZED_DEVICE = 4
	SYSTEM_UPDATE_REQUIRED = 7
	BANNED_DEVICE = 8
	INTERNAL_SERVER_ERROR = 9
	GENERIC = 14
	CHALLENGE_EXPIRED = 15
	WRONG_MAC = 16
	BROKEN_DEVICE = 17

ERROR_MESSAGES = {
	DAuthError.UNAUTHORIZED_DEVICE: "Unauthorized device.",
	DAuthError.SYSTEM_UPDATE_REQUIRED: "System update is required.",
	DAuthError.BANNED_DEVICE: "Device has been banned.",
	DAuthError.INTERNAL_SERVER_ERROR: "Internal Server Error.",
	DAuthError.GENERIC: "Invalid parameter in request.",
	DAuthError.CHALLENGE_EXPIRED: "Invalid parameter in request.",
	DAuthError.WRONG_MAC: "Invalid parameter in request.",
	DAuthError.BROKEN_DEVICE: "This device might be broken."
}

ERROR_STATUS = {
	DAuthError.UNAUTHORIZED_DEVICE: 400,
	DAuthError.SYSTEM_UPDATE_REQUIRED: 400,
	DAuthError.BANNED_DEVICE: 400,
	DAuthError.INTERNAL_SERVER_ERROR: 500,
	DAuthError.GENERIC: 400,
	DAuthError.CHALLENGE_EXPIRED: 400,
	DAuthError.WRONG_MAC: 400,
	DAuthError.BROKEN_DEVICE: 400
}


VALID_SYSTEM_VERSIONS = [
	"CusHY#00080100#OvqIXdglAGfnEd_VQr28t7rUtxNE6LHjMQicnQ9o7zk=",
	"CusHY#00090000#-80vwBkUjWLb5Kpb_cnuTjBZ0rHwZHhN7R1-vg0Ti5c=",
	"CusHY#00090001#qVDSOCehwMDCHyDnkXiTSJ1wEJZHtpRV_CLMKgD-fSw=",
	"CusHY#00090100#vIPNrRbf30SoU8ZJ6uGklMqKAkyjHfdE9m6yLFeChkE=",
	"CusHY#00090200#Uxxmc8gYnfMqxzdZdygZ_OrKo98O7QA65s_EkZnGsDo=",
	"CusHY#000a0000#EmdxOnZjZ9Ihf3Zskt_48pYgowAUeeJccU6tCBIweEc=",
	"CusHY#000a0001#JEuSEdid24qqHqQzfW1tuNsCGcCk-86gcPq0I7M1x18=",
	"CusHY#000a0002#BTOGo0giC7bbrNoi8JEm-FBzmXb2Kgpq4K3OzQrD5l8=",
	"CusHY#000a0003#4mBbTFYnE0Rtmh8NLCVq61rbvx0kJPQUxXkDpwj0V84=",
	"CusHY#000a0100#Vlw9dIEqjxE2F5jDOQPYWXs2p7wIGyDYWXXIyQGdxcE=",
	"CusHY#000a0200#90k0dE_eO7hRcs6ByTZMvgUm4lhEoqAlik96WkznQcQ=",
	"CusHY#000b0000#VyA0fsWi6ZBEOzVsseXIcEfFLqQMgW0tWzN2oJ7viqk=",
	"CusHY#000b0001#iI0rZ0Q2dg3Evhd-8GoYmp-KTE8malKe0GOJgXa-XG8=",
	"CusHY#000c0000#C-BynYNPXdQJNBZjx02Hizi8lRUSIKLwPGa5p8EY1uo=",
	"CusHY#000c0001#YXsU5FTbkUh18QH27L3woGqw5n1gIDpMGbPXM8oACzY=",
	"CusHY#000c0002#6tB3UVnmvT_nsNBMPSD-K1oe0IA1cYvYDyqDCjy2W_I=",
	"CusHY#000c0003#E8Ph6vISWsJtN0E3hsfVRoZMG1Qqkc-qGRlAp-Bs2SI=",
	"CusHY#000c0100#Hzs8Gtp6yKgGKMb732-5Q-NvbQcHCgBh_LQrrpg0bIs=",
	"CusHY#000d0000#r1xneESd4PiTRYIhVIl0bK1ST5L5BUmv_uGPLqc4PPo=",
	"CusHY#000d0100#plps6S3C43QHhkI2oNvYIFjNxQjTcLdUX2_biEI5w2w=",
	"CusHY#000d0200#JFVNVuG9x3V5tRshdD9FdJjgHOmzsrgXHocEPvW5eMM=",
	"CusHY#000d0201#V1i7M7oEhkDaH1lcGlHhGAnyHONMAnTAA6pGdZ7MFqc=",
	"CusHY#000e0000#35hWb15SBXTnbUfTMLBz9sCnfheuRGis0OTZqa7l8yw=",
	"CusHY#000e0100#ctIxSPR4jenzQNGc6y4zXIvzvF75ty53jN0T15Rjtmk=",
	"CusHY#000e0101#uTt4IVydkYqwYArOFR3BzOCmw0MkEeF_tZxHENYDh4E=",
	"CusHY#000e0102#jHk6_VwXVPPl3ijRZ5jRy5MIAcUW_Q2uFdfJ0vrjhCA=",
	"CusHY#000f0000#MJE7we0zvVhAnXN9uCU7fQAM7GiqGHpR5ECuC9G_nuU="
]


def load_keyset(filename):
	keys = {}
	with open(filename) as f:
		lines = f.readlines()
	
	for line in lines:
		line = line.strip()
		if line:
			name, key = line.split("=")
			keys[name.strip()] = bytes.fromhex(key)
	return keys

PROD_KEYS = load_keyset("resources/prod.keys")
DEV_KEYS = load_keyset("resources/dev.keys")


@cached(TTLCache(maxsize=1, ttl=600))
def get_jwt_key():
	with open("instance/private.json") as f:
		return json.load(f)


def make_error(code):
	error = {"code": "%04i" %code, "message": ERROR_MESSAGES[code]}
	return {"errors": [error]}, ERROR_STATUS[code]

def check_banned(device_id):
	now = datetime.datetime.now()
	query = db.Ban.query
	query = query.filter(db.Ban.device_id == device_id)
	query = query.filter((db.Ban.start == None) | (db.Ban.start <= now))
	query = query.filter((db.Ban.end == None) | (db.Ban.end > now))
	ban = query.first()
	if ban:
		return DAuthError.BANNED_DEVICE if ban.permanent else DAuthError.BROKEN_DEVICE
	return DAuthError.OK

def make_challenge():
	# This is custom. I have no idea how the real server does it.
	nonce = secrets.token_bytes(8)
	timestamp = int(time.time() * 1000)
	data = struct.pack(">Q", timestamp) + nonce
	
	aes = AES.new(CHALLENGE_KEY, AES.MODE_ECB)
	ciphertext = aes.encrypt(data)
	signature = hmac.digest(CHALLENGE_KEY, ciphertext, "sha256")[:16]
	return base64.b64encode(ciphertext + signature, b"-_").decode()

def verify_challenge(challenge):
	try:
		challenge = base64.b64decode(challenge, b"-_")
	except binascii.Error:
		return DAuthError.GENERIC
	
	if len(challenge) != 32:
		return DAuthError.GENERIC
	
	signature = hmac.digest(CHALLENGE_KEY, challenge[:16], "sha256")[:16]
	if challenge[16:] != signature:
		return DAuthError.GENERIC
	
	aes = AES.new(CHALLENGE_KEY, AES.MODE_ECB)
	data = aes.decrypt(challenge[:16])
	
	now = int(time.time() * 1000)
	timestamp = struct.unpack_from(">Q", data)[0]
	if timestamp > now:
		return DAuthError.GENERIC
	
	# The challenge is valid for one minute
	if now - timestamp > 60000:
		return DAuthError.CHALLENGE_EXPIRED
	return DAuthError.OK

def calculate_mac(keygen, payload, dt):
	keyset = PROD_KEYS if dt == "NX Prod 1" else DEV_KEYS
	
	key = keyset["master_key_%02x" %(keygen - 1)]
	key = AES.new(key, AES.MODE_ECB).decrypt(keyset["aes_kek_generation_source"])
	key = AES.new(key, AES.MODE_ECB).decrypt(MAC_KEY)
	key = AES.new(key, AES.MODE_ECB).decrypt(MAC_KEYS[keygen])
	
	mac = CMAC.new(key, ciphermod=AES)
	mac.update(payload.encode())
	return base64.b64encode(mac.digest(), b"-_").decode().rstrip("=")

def parse_certificate(certificate):
	# Every device certificate has a hex string that contains
	# 256 encrypted bytes. This is probably the place where stuff
	# such as serial number and device type are stored. I have
	# no idea which format and encryption algorithm are used in
	# real certificates, so this part is custom.
	
	# Extract the subject alternative name
	cert = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
	for i in range(cert.get_extension_count()):
		ext = cert.get_extension(i)
		if ext.get_short_name() == b"subjectAltName":
			info = ext.get_data()
			break
	else:
		return None
	
	# Extract the encrypted blob
	try:
		decoder = asn1.Decoder()
		decoder.start(info)
		decoder.enter()
		decoder.enter()
		tag, value = decoder.read()
		if value != "2.25":
			return None
		decoder.enter()
		tag, value = decoder.read()
		info = bytes.fromhex(value.decode())
	except Exception:
		return None
	
	if len(info) != 256:
		return None
	
	# Verify the signature
	signature = hmac.digest(CERTIFICATE_KEY, info[:-32], "sha256")
	if signature != info[-32:]:
		return None
	
	# Decrypt the blob and parse its contents
	aes = AES.new(CERTIFICATE_KEY, AES.MODE_CBC, iv=info[:16])
	text = aes.decrypt(info[16:-32])
	return json.loads(text.rstrip(b"\0"))

def challenge(version):
	if version < 6:
		return make_error(DAuthError.SYSTEM_UPDATE_REQUIRED)
	
	keygen = request.form.get("key_generation")
	if keygen not in ALLOWED_KEYS[version]:
		return make_error(DAuthError.GENERIC)

	return {
		"challenge": make_challenge(),
		"data": base64.b64encode(MAC_KEYS[int(keygen)], b"-_").decode()
	}

def device_auth_token(version):
	cert = urllib.parse.unquote(request.headers["X-Device-Certificate"])
	info = parse_certificate(cert)
	if info is None:
		return make_error(DAuthError.UNAUTHORIZED_DEVICE)
	
	error = check_banned(info["did"])
	if error != DAuthError.OK:
		return make_error(error)
	
	if version < 6:
		return make_error(DAuthError.SYSTEM_UPDATE_REQUIRED)
	
	keygen = request.form.get("key_generation")
	if keygen not in ALLOWED_KEYS[version]:
		return make_error(DAuthError.GENERIC)
	
	challenge = request.form.get("challenge", "")
	client_id = request.form.get("client_id", "")
	ist = request.form.get("ist", "")
	system_version = request.form.get("system_version", "")
	mac = request.form.get("mac", "")
	
	if not all([challenge, client_id, ist, mac]):
		return make_error(DAuthError.GENERIC)
	
	if system_version not in VALID_SYSTEM_VERSIONS:
		return make_error(DAuthError.GENERIC)
	
	payload = "challenge=%s&client_id=%s&ist=%s&key_generation=%s&system_version=%s" %(
		challenge, client_id, ist, keygen, system_version
	)
	if mac != calculate_mac(int(keygen), payload, info["dt"]):
		return make_error(DAuthError.WRONG_MAC)
	
	error = verify_challenge(challenge)
	if error != DAuthError.OK:
		return make_error(error)
	
	if info["dt"] != os.environ["DEVICE_TYPE"]:
		return make_error(DAuthError.UNAUTHORIZED_DEVICE)
	
	if db.ClientID.query.filter_by(client_id=client_id).first() is None:
		return make_error(DAuthError.GENERIC)
	
	if ist not in ["true", "false"]: return make_error(DAuthError.GENERIC)
	
	system_version = int(system_version.split("#")[1], 16)
	if version == 7 and system_version < 0xD0000:
		return make_error(DAuthError.GENERIC)
	elif version == 6 and system_version < 0xA0000:
		return make_error(DAuthError.SYSTEM_UPDATE_REQUIRED)
	
	iat = int(time.time())
	payload = {
		"sub": info["did"],
		"iss": os.environ["DAUTH_DOMAIN"],
		"aud": client_id,
		"exp": iat + 86400,
		"iat": iat,
		"jti": str(uuid.uuid4()),
		"nintendo": {
			"sn": info["sn"],
			"pc": info["pc"],
			"dt": info["dt"],
			"ist": ist == "true"
		}
	}
	
	key = get_jwt_key()
	headers = {
		"jku": os.environ["DAUTH_JKU"],
		"kid": key["kid"]
	}
	
	token = jwt.encode(payload, key["data"], "RS256", headers)
	return {
		"expires_in": 86400,
		"device_auth_token": token
	}

def edge_token(version):
	cert = urllib.parse.unquote(request.headers["X-Device-Certificate"])
	info = parse_certificate(cert)
	if info is None:
		return make_error(DAuthError.UNAUTHORIZED_DEVICE)
	
	error = check_banned(info["did"])
	if error != DAuthError.OK:
		return make_error(error)
	
	if version < 6:
		return make_error(DAuthError.SYSTEM_UPDATE_REQUIRED)
	
	keygen = request.form.get("key_generation")
	if keygen not in ALLOWED_KEYS[version]:
		return make_error(DAuthError.GENERIC)
	
	challenge = request.form.get("challenge", "")
	client_id = request.form.get("client_id", "")
	ist = request.form.get("ist", "")
	system_version = request.form.get("system_version", "")
	vendor_id = request.form.get("vendor_id", "")
	mac = request.form.get("mac", "")
	
	if not all([challenge, client_id, ist, mac]):
		return make_error(DAuthError.GENERIC)
	if system_version not in VALID_SYSTEM_VERSIONS: 
		return make_error(DAuthError.GENERIC)
	if version >= 7 and not vendor_id:
		return make_error(DAuthError.GENERIC)
	
	payload = "challenge=%s&client_id=%s&ist=%s&key_generation=%s&system_version=%s" %(
		challenge, client_id, ist, keygen, system_version
	)
	if version >= 7:
		payload += "&vendor_id=%s" %vendor_id
	
	if mac != calculate_mac(int(keygen), payload, info["dt"]):
		return make_error(DAuthError.WRONG_MAC)
	
	error = verify_challenge(challenge)
	if error != DAuthError.OK:
		return make_error(error)
	
	if info["dt"] != os.environ["DEVICE_TYPE"]:
		return make_error(DAuthError.UNAUTHORIZED_DEVICE)
	
	client_key = db.ClientID.query.with_entities(db.ClientID.client_key).filter_by(client_id=client_id).scalar()
	if client_key is None:
		return make_error(DAuthError.GENERIC)
	
	if ist not in ["true", "false"]: return make_error(DAuthError.GENERIC)
	if version >= 7 and vendor_id != "akamai":
		return make_error(DAuthError.GENERIC)
	
	system_version = int(system_version.split("#")[1], 16)
	if version == 7 and system_version < 0xD0000:
		return make_error(DAuthError.GENERIC)
	elif version == 6 and system_version < 0xA0000:
		return make_error(DAuthError.SYSTEM_UPDATE_REQUIRED)
	
	payload = {
		"sub": info["did"],
		"sn": info["sn"],
		"id": str(uuid.uuid4())
	}
	
	payload = ".".join("%s=%s" %(key, value) for key, value in payload.items())
	auth = EdgeAuth(key=client_key, payload=payload, window_seconds=86400)
	return {
		"expires_in": 86400,
		"dtoken": auth.generate_acl_token("%2F%2A")
	}


v2_hash = "439528b578b74475d24ec19264097f17d2cc578c8584816b644e7b7fa93044d7"
v3_hash = "59ed5fa1c25bb2aea8c4d73d74b919a94d89ed48d6865b728f63547943b17404"
v4_hash = "fb411cdeda62ff6da97e57c29d6300bc12b6b709869e56906aec88cb42a299cd"

app.add_url_rule("/v3-%s/challenge" %v3_hash, "v3_challenge", lambda: challenge(3), methods=["POST"])
app.add_url_rule("/v4-%s/challenge" %v4_hash, "v4_challenge", lambda: challenge(4), methods=["POST"])
app.add_url_rule("/v5/challenge", "v5_challenge", lambda: challenge(5), methods=["POST"])
app.add_url_rule("/v6/challenge", "v6_challenge", lambda: challenge(6), methods=["POST"])
app.add_url_rule("/v7/challenge", "v7_challenge", lambda: challenge(7), methods=["POST"])

app.add_url_rule("/v1/device_auth_token", "v1_dauth", lambda: device_auth_token(1), methods=["POST"])
app.add_url_rule("/%s/device_auth_token" %v2_hash, "v2_dauth", lambda: device_auth_token(2), methods=["POST"])
app.add_url_rule("/v3-%s/device_auth_token" %v3_hash, "v3_dauth", lambda: device_auth_token(3), methods=["POST"])
app.add_url_rule("/v4-%s/device_auth_token" %v4_hash, "v4_dauth", lambda: device_auth_token(4), methods=["POST"])
app.add_url_rule("/v5/device_auth_token", "v5_dauth", lambda: device_auth_token(5), methods=["POST"])
app.add_url_rule("/v6/device_auth_token", "v6_dauth", lambda: device_auth_token(6), methods=["POST"])
app.add_url_rule("/v7/device_auth_token", "v7_dauth", lambda: device_auth_token(7), methods=["POST"])

app.add_url_rule("/v3-%s/edge_token" %v3_hash, "v3_edge", lambda: edge_token(3), methods=["POST"])
app.add_url_rule("/v4-%s/edge_token" %v4_hash, "v4_edge", lambda: edge_token(4), methods=["POST"])
app.add_url_rule("/v5/edge_token", "v5_edge", lambda: edge_token(5), methods=["POST"])
app.add_url_rule("/v6/edge_token", "v6_edge", lambda: edge_token(6), methods=["POST"])
app.add_url_rule("/v7/edge_token", "v7_edge", lambda: edge_token(7), methods=["POST"])

app.register_error_handler(400, lambda e: make_error(DAuthError.GENERIC))
app.register_error_handler(403, lambda e: make_error(DAuthError.GENERIC))
app.register_error_handler(404, lambda e: make_error(DAuthError.GENERIC))
app.register_error_handler(405, lambda e: make_error(DAuthError.GENERIC))
app.register_error_handler(500, lambda e: make_error(DAuthError.INTERNAL_SERVER_ERROR))
