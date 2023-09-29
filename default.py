import xbmc
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, quote
from urllib.request import urlopen, Request
from urllib.error import URLError
import json  # import the json module

class MyHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path == '/playlist.m3u8':
            try:
                response = urlopen('http://localhost:52104/playlist.m3u8')
                content = response.read().decode('utf-8')  # assuming the content is UTF-8 encoded
                lines = content.split('\n')  # use content instead of response.text
                new_lines = []
                for line in lines:
                    if line.startswith('plugin://'):
                        # URL encode the plugin URL and replace it with the new URL
                        encoded_line = quote(line, safe='')
                        new_url = f'http://192.168.2.9:9191/play?link={encoded_line}'
                        new_lines.append(new_url)
                    else:
                        new_lines.append(line)

                new_content = '\n'.join(new_lines)
                self.send_response(200)
                self.send_header('Content-type', 'application/vnd.apple.mpegurl')
                self.end_headers()
                self.wfile.write(new_content.encode())
            except URLError as e:
                xbmc.log(f"An error occurred: {e}")
                self.send_response(500)
                self.end_headers()

        elif path == '/epg.xml':
            try:
                response = urlopen('http://localhost:52104/epg.xml')
                content = response.read()  # read the content as bytes
                self.send_response(200)
                self.send_header('Content-type', 'application/xml')
                self.end_headers()
                self.wfile.write(content)
            except URLError as e:
                xbmc.log(f"An error occurred: {e}")
                self.send_response(500)
                self.end_headers()

        elif path == '/play':
            query_params = parse_qs(parsed_path.query)
            link = query_params.get('link', [''])[0]
            xbmc.log(f"Link is: {link}")  
            command = json.dumps({
                "jsonrpc": "2.0",
                "method": "Player.Open",
                "params": {
                    "item": {
                        "file": link
                    }
                },
                "id": 1
            })
            response = xbmc.executeJSONRPC(command)
            response_json = json.loads(response)
            if 'error' in response_json:
                xbmc.log(f"Error in JSON-RPC response: {response_json['error']}", level=xbmc.LOGERROR)
            else:
                xbmc.log(f"Kodi JSON-RPC response: {response}")

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
