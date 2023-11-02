from dnslib import server, RR, DNSRecord, QTYPE, A, TXT

class Resolver():

    def __init__(self, a_record):
        self.A_RECORD = A(a_record)
        self.challenge = ""
        pass

    def resolve(self, request: DNSRecord, handler):
        # print(request.get_q().toZone())
        if request.q.qtype == QTYPE.A or request.q.qtype == QTYPE.AAAA:
            reply = request.reply()
            a = RR(request.q.qname, QTYPE.A, rdata=self.A_RECORD, ttl=60)
            reply.add_answer(a)

        if request.q.qtype == QTYPE.TXT:
            reply = request.reply()
            a = RR(request.q.qname, QTYPE.TXT, rdata=TXT(self.challenge), ttl=60)
            reply.add_answer(a)

        return reply
    
    def setChallenge(self, chl):
        self.challenge = chl

class DNSServer:

    def __init__(self, a_record, ip="localhost"):

        self.resolver = Resolver(a_record)

        self.udp_server = server.DNSServer(self.resolver,
                           port=10053,
                           address=ip)

        self.udp_server.start_thread()
        print("Starting DNS Server")

        pass

    def setupChallenge(self, token):
        self.resolver.setChallenge(token)
        pass

