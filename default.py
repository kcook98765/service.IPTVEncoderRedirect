from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import requests

class MyHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path == '/playlist.m3u8':
            response = requests.get('http://localhost:52104/playlist.m3u8')
            self.send_response(200)
            self.send_header('Content-type', 'application/vnd.apple.mpegurl')
            self.end_headers()
            self.wfile.write(response.content)

        elif path == '/epg.xml':
            response = requests.get('http://localhost:52104/epg.xml')
            self.send_response(200)
            self.send_header('Content-type', 'application/xml')
            self.end_headers()
            self.wfile.write(response.content)

        elif path == '/play':
            query_params = parse_qs(parsed_path.query)
            link = query_params.get('link', [''])[0]  
            print(f"Link is: {link}")  
            
            # Sending a 302 redirect response
            redirect_url = 'http://example.com'  # Replace with your redirect URL
            self.send_response(302)
            self.send_header('Location', redirect_url)
            self.end_headers()

        else:
            self.send_response(404)
            self.end_headers()

def run():
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, MyHandler)
    httpd.serve_forever()

if __name__ == '__main__':
    run()
