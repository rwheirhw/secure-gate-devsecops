from http.server import HTTPServer, BaseHTTPRequestHandler


class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"SecureGate demo application")


server = HTTPServer(("0.0.0.0", 8000), Handler)

print("Application running on port 8000")

server.serve_forever()