import re
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

from base64 import urlsafe_b64encode
import json

from OpenSSL import crypto # Usefull for X509 request

cert_key = crypto.PKey()
cert_key.generate_key(crypto.TYPE_RSA, 2048)

    

class JWK:
    JWKi = None
    ec_key = None
    
    def __init__(self) -> None:
        JWK.ec_key = ECC.generate(curve='P-256')
        self.crv = JWK.ec_key.curve
        self.kty = "EC"
        self.x = Base64URL(JWK.ec_key.pointQ.x.to_bytes())
        self.y = Base64URL(JWK.ec_key.pointQ.y.to_bytes())

        pass
    
    def generateJWK():
        JWK.JWKi = JWK()

class JWS:
    def __init__(self, payload, url, kid = None, nonce = None) -> None:

        header = json.dumps(self.getHeader(nonce, url, kid), separators=(",", ":"))
        payload = "" if payload == "" else json.dumps(payload, separators=(",", ":"))

        self.protected = Base64URL(header)
        self.payload = Base64URL(payload)
        self.signature = self.signJWS(header, payload)
        
        pass
    
    def getHeader(self, nonce, url, kid) -> dict:
        header = {
            "alg": "ES256",
            "nonce": nonce,
            "url": url
        }
        if kid:
            header["kid"] = kid
        else:
            header["jwk"] = JWK.JWKi.__dict__
        
        return header
    
    def signJWS(self, header, payload) -> str:
        m = Base64URL(header) + '.' + Base64URL(payload)
        h = SHA256.new(bytes(m, 'utf-8'))
        signer = DSS.new(JWK.ec_key, 'fips-186-3')
        s = signer.sign(h)
        return Base64URL(s)
    
    def toDict(self) -> dict:
        return self.__dict__

def KeyAuthGen(token, isHTTP = False) -> str:
    accKey = json.dumps(JWK.JWKi.__dict__, separators=(",", ":"))
    thumbprint = SHA256.new(bytes(accKey, 'utf-8')).digest()
    keyAuth = token + "." + Base64URL(thumbprint)
    return keyAuth if isHTTP else Base64URL(SHA256.new(bytes(keyAuth, 'utf-8')).digest())

def csr(domains) -> str:

    company = re.findall('\w+\.\w+$', domains[0])[0]
    domains = ["DNS:"+x for x in domains]

    request = crypto.X509Req()
    request.get_subject().CN = company
    request.add_extensions([crypto.X509Extension(b"subjectAltName", False, bytes(", ".join(domains), 'utf-8'))])

    request.set_pubkey(cert_key)
    request.sign(cert_key, 'sha256')

    #save private key
    f = open("tmp/key.pem", "wb")
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, cert_key))
    f.close()

    return Base64URL(crypto.dump_certificate_request(crypto.FILETYPE_ASN1, request))

def convertCertificate(cert):
    c = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    return Base64URL(crypto.dump_certificate(crypto.FILETYPE_ASN1, c))

def Base64URL(input) -> str:
    if not isinstance(input, bytes):
        input = bytes(input, 'utf-8')
    return str(urlsafe_b64encode(input).rstrip(b'='), 'utf-8')