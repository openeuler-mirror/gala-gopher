from http.server import HTTPServer, BaseHTTPRequestHandler


"""
example:
    curl -X GET http://localhost:8888
    curl -X POST -d "5" http://localhost:8888
"""

class Request(BaseHTTPRequestHandler):
    timeout = 5
    server_version = "Apache"

    def do_GET(self):
        if self.path == '/api':
            self.send_response(200)
            self.send_header("type", "get")
            self.end_headers()

            msg = 123
            msg = str(msg).encode()

            self.wfile.write(msg)
        else:
            self.send_error(404, "path api Not Found")


    def do_POST(self):
        if self.path == '/api':
            data = self.rfile.read(int(self.headers['content-length']))
            data = data.decode()

            self.send_response(200)
            self.send_header("type", "post")
            self.end_headers()

            msg = int(data) * 2
            msg = str(msg).encode()
            self.wfile.write(msg)
        else:
            self.send_error(404, "path api Not Found")


host = ('localhost', 8888)
server = HTTPServer(host, Request)
server.serve_forever()
