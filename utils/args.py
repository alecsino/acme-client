import argparse
from xmlrpc.client import Boolean

def parseArgs():
    parser = argparse.ArgumentParser(prog = 'ACME Client')
    parser.add_argument("challenge_type", choices=['dns01', 'http01'])
    parser.add_argument("--dir", required=True)
    parser.add_argument("--record", dest="dns_record", required=True)
    parser.add_argument("--domain", dest="domains", required=True, action="append")
    parser.add_argument("--revoke", action="store_true")
    return parser.parse_args()