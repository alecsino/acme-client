import time
from utils.crypto import KeyAuthGen, csr, convertCertificate, JWK
from utils.req import ACMEReq
from servers.dns import DNSServer
from servers.http import BaseHTTPServer
from utils.args import parseArgs

ARGS = parseArgs()
DNS_Server = DNSServer(ARGS.dns_record, ip="0.0.0.0")
HTTP_Server = BaseHTTPServer(port=5002, ip="0.0.0.0")
Shutdown_Server = BaseHTTPServer(port=5003, shutdownServer=True, ip="0.0.0.0")

class ACMEClient:

    def __init__(self) -> None:
        self.ENDPOINTS = ACMEReq("get", ARGS.dir).toJSON()
        self.KID = None

        if not self.ENDPOINTS:
            print("Terminating because the certificate of ACME server is not valid")
            Shutdown_Server.shutdown()
        ACMEReq("get", self.ENDPOINTS["newNonce"])

        self.createAccount()
        pass

    def createAccount(self):
        JWK.generateJWK()
        body = {"termsOfServiceAgreed": True}
        accRequest = ACMEReq("post", self.ENDPOINTS["newAccount"], json=body)

        if not accRequest.isOk():
            return self.createAccount()
        
        self.KID = accRequest.getHeader("Location")
        self.createOrder()

    def createOrder(self):
        payload = { "identifiers": [ {"type": "dns", "value": x} for x in ARGS.domains] }

        orderRequest = ACMEReq("post", self.ENDPOINTS["newOrder"], json=payload, kid=self.KID)

        if 'authorizations' not in orderRequest.toJSON():
            self.createAccount()
            return

        self.challenges = orderRequest.toJSON()["authorizations"]
        self.finalizeUrl = orderRequest.toJSON()["finalize"]

        for chal in self.challenges:
            if not self.solveChall(chal):
                self.createAccount()
                return

        self.generateCert()

    def solveChall(self, challenge):
        challRequest = ACMEReq("post", challenge, json="", kid=self.KID).toJSON()
        challengeTypes = challRequest["challenges"]
        for type in challengeTypes:
            if ARGS.challenge_type == "http01" and type["type"] == "http-01":
                return self.solveHTTP(type)
            elif ARGS.challenge_type == "dns01" and type["type"] == "dns-01": 
                return self.solveDns(type)
        
        raise Exception("Could not find challenge")
    
    def solveHTTP(self, challenge):
        keyAuth = KeyAuthGen(challenge['token'], True)
        HTTP_Server.addEndpoint("/.well-known/acme-challenge/"+challenge['token'], keyAuth)
        return self.confirmChallenge(challenge)

    def solveDns(self, challenge):
        keyAuth = KeyAuthGen(challenge['token'])
        DNS_Server.setupChallenge(keyAuth)
        return self.confirmChallenge(challenge)

    def confirmChallenge(self, challenge):
        confirm = ACMEReq("post", challenge['url'], json={}, kid=self.KID).toJSON()

        #polling
        while confirm["status"] != "valid":
            print(f"CH: {confirm['status']}")
            if confirm["status"] == 'invalid':
                print(confirm)
                return False

            time.sleep(1)
            confirm = ACMEReq("post", challenge['url'], json="", kid=self.KID).toJSON()
        
        return True

    def generateCert(self):
        finalizeReq = ACMEReq("post", self.finalizeUrl, json={"csr": csr(ARGS.domains)}, kid=self.KID)
        certUrl = ACMEReq("post", finalizeReq.getHeader("Location"), json="", kid=self.KID)
        
        while certUrl.toJSON()["status"] != "valid":
                print(f"CERT: {certUrl.toJSON()['status']}")
                time.sleep(3)
                certUrl = ACMEReq("post", finalizeReq.getHeader("Location"), json="", kid=self.KID)

        cert = ACMEReq("post", certUrl.toJSON()["certificate"], json="", kid=self.KID) #Finally download the certificate
        self.CERTIFICATE = cert.response

        f = open("tmp/cert.pem", "w")
        f.write(self.CERTIFICATE)
        f.close()

        if ARGS.revoke:
            self.revokeCert()

        BaseHTTPServer(port=5001, isHTTPS = True, ip="0.0.0.0")

    def revokeCert(self):
        b64Cert = convertCertificate(self.CERTIFICATE)
        ACMEReq("post", self.ENDPOINTS["revokeCert"], json={ "certificate": b64Cert }, kid=self.KID)

ACMEClient()