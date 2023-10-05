import xbmc
import xbmcaddon
import xbmcvfs
import os
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from concurrent.futures import ThreadPoolExecutor
import json  # import the json module
import time
import threading
import sqlite3



ENABLE_LOGGING = True # FALSE to shut off

ADDON = xbmcaddon.Addon()
ADDON_PATH = ADDON.getAddonInfo("path")
ADDON_NAME = ADDON.getAddonInfo("name")
ADDON_ID = ADDON.getAddonInfo("id")


from database_helper import (
    create_database, populate_kodi_boxes, query_database, 
    modify_database, store_address, store_link,
    insert_into_active_streams, update_active_stream_status,
    truncate_addresses_table
)

from kodi_rpc import (
    send_jsonrpc, stop_kodi_playback, get_encoder_url_for_link, 
    get_available_kodi_box
)



# Read Master settings
master_ip = ADDON.getSetting('master_ip')
master_encoder_url = ADDON.getSetting('master_encoder_url')
server_port_setting = ADDON.getSetting('server_port')
server_port = int(server_port_setting) if server_port_setting else 9191

# Read Slave settings
slave_1_ip = ADDON.getSetting('slave_1_ip')
slave_1_encoder_url = ADDON.getSetting('slave_1_encoder_url')

slave_2_ip = ADDON.getSetting('slave_2_ip')
slave_2_encoder_url = ADDON.getSetting('slave_2_encoder_url')

slave_3_ip = ADDON.getSetting('slave_3_ip')
slave_3_encoder_url = ADDON.getSetting('slave_3_encoder_url')

KODI_BOXES = [
    {
        "Actor": "Master",
        "IP": master_ip,
        "Encoder_URL": master_encoder_url
    },
    {
        "Actor": "Slave",
        "IP": slave_1_ip,
        "Encoder_URL": slave_1_encoder_url
    },
    {
        "Actor": "Slave",
        "IP": slave_2_ip,
        "Encoder_URL": slave_2_encoder_url
    },
    {
        "Actor": "Slave",
        "IP": slave_3_ip,
        "Encoder_URL": slave_3_encoder_url
    }
]

play_request_lock = threading.Lock()
active_proxies = {}  # Dictionary to maintain active proxies per link
proxy_clients = {}  # Dictionary to maintain active clients for each proxy

def log_message(message, level=xbmc.LOGDEBUG):
    if ENABLE_LOGGING or level == xbmc.LOGERROR:
        xbmc.log(message, level=level)

class ProxyHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.encoder_connection = None
        self.associated_kodi = None
        super().__init__(*args, **kwargs)

    def handle_proxy_request(self, link):
        global proxy_clients
        
        log_message("Handling proxy request for link: {}".format(link))

        try:
            # Get encoder URL based on link (or however you want to fetch it)
            encoder_url = get_encoder_url_for_link(link)
            log_message(f"Encoder URL fetched for link: {link} is {encoder_url}")

            # Open a connection to the encoder
            self.encoder_connection = urlopen(encoder_url)
            log_message(f"Connection established to encoder: {encoder_url}")

            # While we're reading data from the encoder, write to client
            chunk = self.encoder_connection.read(4096)
            while chunk:
                self.wfile.write(chunk)
                chunk = self.encoder_connection.read(4096)

        except Exception as e:
            log_message(f"Proxy error for link {link}: {e}", level=xbmc.LOGERROR)

        finally:
            if self.encoder_connection:
                self.encoder_connection.close()
                log_message("Encoder connection closed.")

    def finish(self):
        # Client disconnection is handled here
        global proxy_clients

        if self.associated_kodi and self.client_address in proxy_clients.get(self.associated_kodi, set()):
            proxy_clients[self.associated_kodi].remove(self.client_address)
            
            if not proxy_clients[self.associated_kodi]:
                stop_kodi_playback(self.associated_kodi)

        super().finish()

    def do_GET(self):
        global active_proxies, proxy_clients

        parsed_path = urlparse(self.path)
        if parsed_path.path == '/proxy':
            link = parse_qs(parsed_path.query).get('link', [''])[0]

            # Check if an active proxy exists for this link
            if link not in active_proxies:
                encoder_url = get_encoder_url_for_link(link)
                active_proxies[link] = {
                    'encoder_connection': urlopen(encoder_url),
                    'clients': set()  # Maintain clients for this link
                }

            active_proxies[link]['clients'].add(self)

            try:
                # Distribute data from the encoder to the client
                while True:
                    chunk = active_proxies[link]['encoder_connection'].read(4096)
                    if not chunk:
                        break
                    self.wfile.write(chunk)

            except Exception as e:
                # Handle client disconnect or other errors
                active_proxies[link]['clients'].remove(self)
                if not active_proxies[link]['clients']:
                    active_proxies[link]['encoder_connection'].close()
                    del active_proxies[link]

class MyHandler(BaseHTTPRequestHandler):

    def handle_error(self, e, error_message=None):
        log_message(f"HTTP request handling error: {e}", level=xbmc.LOGERROR)
        self.send_response(500)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        if error_message:
            self.wfile.write(error_message.encode())

    def do_GET(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path == '/playlist.m3u8':
            log_message("Received request for playlist.")
            try:
                response = urlopen('http://localhost:52104/playlist.m3u8')
                content = response.read().decode('utf-8')  # assuming the content is UTF-8 encoded
                lines = content.split('\n')  # use content instead of response.text
                new_lines = []
                for line in lines:
                    if line.startswith('plugin://'):
                        # URL encode the plugin URL and replace it with the new URL
                        encoded_line = quote(line, safe='')
                        new_url = f'http://{master_ip}:{server_port}/play?link={encoded_line}'
                        new_lines.append(new_url)
                    else:
                        new_lines.append(line)

                new_content = '\n'.join(new_lines)
                self.send_response(200)
                self.send_header('Content-type', 'application/vnd.apple.mpegurl')
                self.end_headers()
                self.wfile.write(new_content.encode())
            except Exception as e:
                self.handle_error(e, "Internal server error")


        elif path == '/epg.xml':
            log_message("Received request for EPG.")
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
            log_message("Received play request.")
            with play_request_lock:
                query_params = parse_qs(parsed_path.query)
                link = query_params.get('link', [''])[0]

                # Store the link as soon as it's gathered
                store_link(link)

                # Check if the link exists in the active_streams table
                encoder_url = get_encoder_url_for_link(link)
                if encoder_url:
                    # Redirect to the encoder URL
                    # Redirect the caller to the proxy, not the encoder
                    proxy_url = f"http://{master_ip}:{server_port + 1}/proxy?link={quote(link)}"
                    self.send_response(302)
                    self.send_header('Location', proxy_url)
                    self.end_headers()
                else:
                    # Find an available Kodi box
                    available_kodi_box = get_available_kodi_box()
                    if available_kodi_box:
                        # Log to the table that you're using this Kodi box
                        insert_into_active_streams(available_kodi_box['IP'], 'Active', link)
            
                        # Send the JSON-RPC to the Kodi box
                        payload = {
                            "jsonrpc": "2.0",
                            "method": "Player.Open",
                            "params": {
                                "item": {
                                    "file": link
                                }
                            },
                            "id": 1
                        }
                        kodi_url = "local" if available_kodi_box["Actor"] == "Master" else f"http://{available_kodi_box['IP']}:8080/jsonrpc"
                        response_json = send_jsonrpc(kodi_url, payload)
            
                        if response_json and 'error' in response_json:
                            xbmc.log(f"Error in JSON-RPC response: {response_json['error']}", level=xbmc.LOGERROR)
                            # Handle the error (e.g., send a failure response or try another Kodi box)
                        else:
                            # Redirect the caller
                            self.send_response(302)
                            self.send_header('Location', available_kodi_box['Encoder_URL'])
                            self.end_headers()
                    else:
                        self.send_response(503)  # This sets the HTTP status code to 503
                        self.send_header('Content-Type', 'text/plain')  # Optional, sets the content type of the response
                        self.end_headers()  # This ends the HTTP headers section
    
                # Check if the Kodi instance has been active for over 4 hours
                rows = query_database('SELECT timestamp FROM links WHERE link = ?', (link,))
                if rows:
                    timestamp_str = rows[0][0]
                    try:
                        timestamp = time.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                        current_time = time.time()
                        duration = current_time - time.mktime(timestamp)
                
                        if duration > (4 * 60 * 60):  # 4 hours in seconds
                            associated_kodi_ip = get_kodi_for_link(link)  # This method should return the Kodi IP associated with a link
                            stop_kodi_playback(associated_kodi_ip)
                    except ValueError:
                        log_message(f"Error parsing timestamp: {timestamp_str} for link: {link}", level=xbmc.LOGERROR)

MAX_WORKERS = 10  # Adjust this based on the maximum number of simultaneous threads you expect

def run():
    try:
        log_message("Starting server...")
        log_message("Creating database...")
        create_database()
        log_message("Populating Kodi boxes...")
        populate_kodi_boxes()
        
        # Main server (synchronous)
        log_message(f"Starting main server on port {server_port}...")
        server_address = ('', server_port)
        main_httpd = HTTPServer(server_address, MyHandler)  # Just HTTPServer for synchronous behavior

        # Proxy server (asynchronous to handle multiple clients)
        log_message(f"Starting proxy server on port {server_port + 1}...")
        proxy_address = ('', server_port + 1)  # Assuming the proxy runs on the next port
        proxy_httpd = ThreadingHTTPServer(proxy_address, ProxyHandler)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            main_future = executor.submit(main_httpd.serve_forever)
            proxy_future = executor.submit(proxy_httpd.serve_forever)
            
            log_message("Both servers are now running.")

            # Wait for both servers to complete. In practice, these servers run forever unless an exception occurs.
            main_future.result()
            proxy_future.result()

    except Exception as e:
        log_message(f"Main execution error: {e}", level=xbmc.LOGERROR)

if __name__ == '__main__':
    log_message("Starting application...")
    run()
    log_message("Application terminated.")