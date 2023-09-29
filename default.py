from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, quote
import requests

class MyHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path == '/playlist.m3u8':
            response = requests.get('http://localhost:52104/playlist.m3u8')
            lines = response.text.split('\n')
            new_lines = []
            for line in lines:
                if line.startswith('plugin://'):
                    # URL encode the plugin URL and replace it with the new URL
                    encoded_line = quote(line, safe='')
                    new_url = f'http://192.168.2.9?link={encoded_line}'
                    new_lines.append(new_url)
                else:
                    new_lines.append(line)
            
            new_content = '\n'.join(new_lines)
            self.send_response(200)
            self.send_header('Content-type', 'application/vnd.apple.mpegurl')
            self.end_headers()
            self.wfile.write(new_content.encode())

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
            
            # Send a request to Kodi's JSON-RPC API to open the plugin URL
            kodi_url = 'http://localhost:8080/jsonrpc'  # Replace with your Kodi's JSON-RPC URL
            headers = {'content-type': 'application/json'}
            data = {
                "jsonrpc": "2.0",
                "method": "Player.Open",
                "params": {
                    "item": {
                        "file": link
                    }
                },
                "id": 1
            }
            response = requests.post(kodi_url, json=data, headers=headers)
            print(f"Kodi JSON-RPC response: {response.json()}")

            # Sending a 302 redirect response
            redirect_url = 'http://192.168.2.168/0.ts'
            self.send_response(302)
            self.send_header('Location', redirect_url)
            self.end_headers()

        else:
            self.send_response(404)
            self.end_headers()

def run():
    server_address = ('', 9191)
    httpd = HTTPServer(server_address, MyHandler)
    httpd.serve_forever()

if __name__ == '__main__':
    run()
