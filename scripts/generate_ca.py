
from OpenSSL import crypto
import datetime


name = input("Common name [NintendoNXCA2Prod1]: ")
if not name:
	name = "NintendoNXCA2Prod1"


key = crypto.PKey()
key.generate_key(crypto.TYPE_RSA, 2048)


now = datetime.datetime.now()

cert = crypto.X509()
cert.set_version(2)

subject = cert.get_subject()
subject.countryName = "JP"
subject.stateOrProvinceName = "Kyoto"
subject.localityName = "Kyoto"
subject.organizationName = "Nintendo Co.,Ltd."
subject.commonName = name

cert.set_issuer(subject)
cert.set_notBefore(now.strftime("%Y%m%d%H%M%SZ").encode())
cert.set_notAfter(b"20491208120000Z")
cert.set_pubkey(key)

cert.add_extensions([
	crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
	crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert)
])
cert.add_extensions([
	crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=cert)
])

cert.sign(key, "sha256")

print()
print(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode())
print(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode())
