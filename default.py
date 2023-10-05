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
import datetime

ENABLE_LOGGING = True # FALSE to shut off

# Constants
CLEANUP_INTERVAL_SECONDS = 3600  # This will check for cleanup every hour. Adjust as needed.
MAX_LINK_IDLE_TIME_SECONDS = 3600 * 1  # Remove links that have been idle for 1 hour.

# Add an additional dictionary to track the last access time of each link.
last_accessed_links = {}
last_accessed_links_lock = threading.Lock()


ADDON = xbmcaddon.Addon()

# Read Master settings
# master_ip = ADDON.getSetting('master_ip')
# master_encoder_url = ADDON.getSetting('master_encoder_url')

master_ip = '192.168.2.9'
master_encoder_url = 'http://192.168.2.168/0.ts'
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
        "Encoder_URL": master_encoder_url,
        "Status": "IDLE"
    },
    {
        "Actor": "Slave",
        "IP": slave_1_ip,
        "Encoder_URL": slave_1_encoder_url,
        "Status": "IDLE"
    },
    {
        "Actor": "Slave",
        "IP": slave_2_ip,
        "Encoder_URL": slave_2_encoder_url,
        "Status": "IDLE"
    },
    {
        "Actor": "Slave",
        "IP": slave_3_ip,
        "Encoder_URL": slave_3_encoder_url,
        "Status": "IDLE"
    }
]

play_request_lock = threading.Lock()

active_proxies = {}  # Dictionary to maintain active proxies per link
active_proxies_lock = threading.Lock()

proxy_clients = {}  # Dictionary to maintain active clients for each proxy
proxy_clients_lock = threading.Lock()

active_links = {} # link: kodi_box_info
active_links_lock = threading.Lock()

def log_message(message, level=xbmc.LOGDEBUG):
    if ENABLE_LOGGING or level == xbmc.LOGERROR:
        xbmc.log(message, level=level)

def get_available_kodi_box(link):
    with active_links_lock:
        # Return the Kodi box if it's already playing the link
        if link in active_links:
            for box in KODI_BOXES:
                if box["IP"] == active_links[link]:
                    return box
        else:
            # Find an available Kodi box
            for box in KODI_BOXES:
                if box["Status"] == "IDLE":
                    box["Status"] = "PLAYING"  # Mark the box as PLAYING
                    active_links[link] = box["IP"]
                    return box
    return None


def start_kodi_playback(kodi_box, link):
    log_message(f"Starting playback on Kodi box with IP: {kodi_box_ip} for {link}", level=xbmc.LOGDEBUG)
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
    kodi_url = "local" if kodi_box["Actor"] == "Master" else f"http://{kodi_box['IP']}:8080/jsonrpc"
    response_json = send_jsonrpc(kodi_url, payload)
    if response_json and 'error' in response_json:
        log_message(f"Error in JSON-RPC response: {response_json['error']}", level=xbmc.LOGERROR)
        # Handle the error, maybe raise an exception or return an error flag.


def stop_kodi_playback(kodi_box_ip):
    # Send a command to stop playback on the specified Kodi box.
    log_message(f"Stopping playback on Kodi box with IP: {kodi_box_ip}", level=xbmc.LOGDEBUG)
    payload = {
        "jsonrpc": "2.0",
        "method": "Player.Stop",
        "params": {
            "playerid": 1
        },
        "id": 1
    }
    kodi_url = "local" if kodi_box["Actor"] == "Master" else f"http://{kodi_box['IP']}:8080/jsonrpc"
    response_json = send_jsonrpc(kodi_url, payload)
    if response_json and 'error' in response_json:
        log_message(f"Error in JSON-RPC response: {response_json['error']}", level=xbmc.LOGERROR)
    # After successfully stopping playback, mark the box as IDLE
    for box in KODI_BOXES:
        if box["IP"] == kodi_box_ip:
            box["Status"] = "IDLE"
            break

def cleanup_stale_entries():
    global active_proxies, proxy_clients, active_links, last_accessed_links
    
    while True:
        time.sleep(CLEANUP_INTERVAL_SECONDS)

        # Find links that haven't been accessed recently.
        stale_links = set()
        current_time = datetime.datetime.now()

        with last_accessed_links_lock:
            for link, last_access_time in last_accessed_links.items():
                if (current_time - last_access_time).total_seconds() > MAX_LINK_IDLE_TIME_SECONDS:
                    stale_links.add(link)

            # Remove the stale links from our tracking
            for link in stale_links:
                del last_accessed_links[link]

        # Now, clean up resources associated with stale links
        with active_proxies_lock:
            for link in stale_links:
                if link in active_proxies:
                    active_proxies[link]['encoder_connection'].close()
                    del active_proxies[link]

        with proxy_clients_lock:
            for link in stale_links:
                if link in proxy_clients:
                    del proxy_clients[link]

        with active_links_lock:
            for link in stale_links:
                if link in active_links:
                    del active_links[link]




class ProxyHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.encoder_connection = None
        self.associated_kodi = None
        super().__init__(*args, **kwargs)

    def handle_proxy_request(self, link):
        global proxy_clients
        
        log_message("Handling proxy request for link: {}".format(link))
        with last_accessed_links_lock:
            last_accessed_links[link] = datetime.datetime.now()

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
        global proxy_clients, active_links
        with proxy_clients_lock:  # Acquire the lock
            if self.associated_kodi and self.client_address in proxy_clients.get(self.associated_kodi, set()):
                proxy_clients[self.associated_kodi].remove(self.client_address)
                
                # If no more clients are accessing the proxy for the Kodi box, shut it down and stop playback on the Kodi box.
                if not proxy_clients[self.associated_kodi]:
                    stop_kodi_playback(self.associated_kodi)
                    with active_links_lock:
                        for link, box_ip in active_links.items():
                            if box_ip == self.associated_kodi:
                                del active_links[link]
                                break
        super().finish()

    def do_GET(self):
        global active_proxies, active_links
        parsed_path = urlparse(self.path)
        if parsed_path.path == '/proxy':
            link = parse_qs(parsed_path.query).get('link', [''])[0]
            with active_proxies_lock:  # Assuming you've created this lock at the top
                if link not in active_proxies:
                    # Initialize this link's proxy info
                    encoder_url = get_encoder_url_for_link(link)  # Implement this function to get encoder URL for a link
                    active_proxies[link] = {
                        'encoder_connection': urlopen(encoder_url),
                        'clients': set()
                    }

                # Add current client to this link's clients
                active_proxies[link]['clients'].add(self.client_address)

                try:
                    # Distribute data from the encoder to the client
                    while True:
                        chunk = active_proxies[link]['encoder_connection'].read(4096)
                        if not chunk:
                            break
                        self.wfile.write(chunk)

                except Exception as e:
                    # Handle client disconnect or other errors
                    active_proxies[link]['clients'].remove(self.client_address)

                    # If no more clients are accessing this link, stop the Kodi box playing it
                    if not active_proxies[link]['clients']:
                        stop_kodi_playback(active_links[link])  # Assuming you've implemented this function to stop playback
                        del active_links[link]
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
                available_kodi_box = get_available_kodi_box(link)
                if available_kodi_box:
                    # If the link is already playing on a Kodi box, just redirect to its encoder URL
                    encoder_url = available_kodi_box['Encoder_URL']
                else:
                    # Else, initiate playback on a Kodi box and then redirect
                    available_kodi_box = get_available_kodi_box(None)
                    if available_kodi_box:
                        start_kodi_playback(available_kodi_box, link)  # Implement the start_kodi_playback function
                        encoder_url = available_kodi_box['Encoder_URL']
                        with active_links_lock:
                            active_links[link] = available_kodi_box["IP"]
                    else:
                        self.send_error(503, "All Kodi boxes are in use.")
                        return
                with last_accessed_links_lock:
                    last_accessed_links[link] = datetime.datetime.now()
                proxy_url = f"http://{master_ip}:{server_port + 1}/proxy?link={quote(link)}"
                self.send_response(302)
                self.send_header('Location', proxy_url)
                self.end_headers()                
    

MAX_WORKERS = 10  # Adjust this based on the maximum number of simultaneous threads you expect

def run():
    try:
        log_message("Starting server...")
        
        # Main server (synchronous)
        log_message(f"Starting main server on port {server_port}...")
        server_address = ('', server_port)
        main_httpd = HTTPServer(server_address, MyHandler)  # Just HTTPServer for synchronous behavior

        # Proxy server (asynchronous to handle multiple clients)
        log_message(f"Starting proxy server on port {server_port + 1}...")
        proxy_address = ('', server_port + 1)  # Assuming the proxy runs on the next port
        proxy_httpd = ThreadingHTTPServer(proxy_address, ProxyHandler)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            cleanup_future = executor.submit(cleanup_stale_entries)
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