from .crypto import JWS
import requests

REQS = {
    'get': requests.get,
    'post': requests.post,
    'head': requests.head
}

CTYPE = {'Content-type': 'application/jose+json'}

class ACMEReq:

    last_nonce = None

    def __init__(self, type: str, url: str, **args) -> None:
        self.url = url
        self.type = type
        self.kid = args.pop('kid', None)

        if type == 'post':
            args['headers'] = CTYPE
            self.body = args['json']

        self._request(**args)

        pass
    
    def _request(self, **args):

        if self.type == 'post':
            args['json'] = JWS(self.body, self.url, kid = self.kid, nonce = ACMEReq.last_nonce).toDict()

        #Catch SSL error if cert not valid
        try:
            self.request = REQS[self.type](self.url, verify="pebble.minica.pem", **args)
        except requests.exceptions.SSLError:
            self.request = None
            return
                
        ACMEReq.last_nonce = self.getHeader('Replay-Nonce')
        
        #nonce rejection
        if not self.request.ok:
            to_json = self.toJSON()
            if 'type' in to_json and 'urn:ietf:params:acme:error:badNonce' in to_json['type']:
                return self._request(**args)

        self.response = self.request.text

    def getHeader(self, header: str):
        return self.request.headers.get(header)
    
    def toJSON(self):
        if self.request is not None and 'json' in self.getHeader("Content-Type"):
            return self.request.json()
    
    def isOk(self):
        return self.request.ok
