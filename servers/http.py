from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import sys
import threading

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    endpoints = {}
    text_endpoints = {}

    def do_GET(self):
        if self.path in SimpleHTTPRequestHandler.endpoints:
            return SimpleHTTPRequestHandler.endpoints[self.path](self)

        if self.path in SimpleHTTPRequestHandler.text_endpoints:
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            return self.wfile.write(bytes(SimpleHTTPRequestHandler.text_endpoints[self.path], 'utf-8'))
        
        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args): #Disable logging
        return

class BaseHTTPServer:
    def __init__(self, port = 5000, shutdownServer = False, isHTTPS = False, ip="localhost"):
        self.httpd = HTTPServer((ip, port), SimpleHTTPRequestHandler)

        if isHTTPS:
            self.httpd.socket = ssl.wrap_socket (self.httpd.socket, keyfile="tmp/key.pem", certfile='tmp/cert.pem', server_side=True)
        
        if shutdownServer:
            self.addEndpoint('/shutdown', shutdown)

        print("Starting HTTP" + ('s' if isHTTPS else '') + " server :" + str(port))

        self.thread = threading.Thread(target=self.httpd.serve_forever)
        self.thread.daemon = not shutdownServer
        self.thread.start()

        pass

    def addEndpoint(self, path, func):
        if isinstance(func, str):
            SimpleHTTPRequestHandler.text_endpoints[path] = func
        else:
            SimpleHTTPRequestHandler.endpoints[path] = func

    def shutdown(self):
        self.httpd.shutdown()
        sys.exit()

def shutdown(req):
    req.send_response(200)
    req.end_headers()

    print("Received shutdown command")
    sys.exit()
