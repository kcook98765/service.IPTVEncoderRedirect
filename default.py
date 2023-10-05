import xbmc, xbmcaddon, xbmcvfs, xbmcgui
import os, json, time, threading, datetime, socket
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from concurrent.futures import ThreadPoolExecutor

ADDON = xbmcaddon.Addon()

ENABLE_LOGGING = True # FALSE to shut off

CLEANUP_INTERVAL_SECONDS = 3600  # This will check for cleanup every hour. Adjust as needed.
MAX_LINK_IDLE_TIME_SECONDS = 3600 * 1  # Remove links that have been idle for 1 hour.

# Add an additional dictionary to track the last access time of each link.
last_accessed_links = {}
last_accessed_links_lock = threading.Lock()

# master_ip = ADDON.getSetting('master_ip')
# master_encoder_url = ADDON.getSetting('master_encoder_url')

assigned_ports = []

def log_message(message, level=xbmc.LOGDEBUG):
    if ENABLE_LOGGING or level == xbmc.LOGERROR:
        xbmc.log(message, level=level)


def find_available_port(start_port, end_port):
    for port in range(start_port, end_port + 1):
        if port not in assigned_ports:
            if is_port_available(port):
                assigned_ports.append(port)
                return port
    return None

def is_port_available(port):
    # Check if a given port is available
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.bind(("localhost", port))
            return True
    except (socket.error, OSError):
        return False

def initialize_kodi_boxes():
    start_port = 49152  # Start of dynamic/private port range
    end_port = 65535    # End of dynamic/private port range
    kodi_boxes = []

    # Master Kodi instance
    master_proxy_port = find_available_port(start_port, end_port)
    if master_proxy_port is None:
        log_message("No available port found for Master Kodi proxy.", level=xbmc.LOGERROR)
    else:
        master_server_port = ADDON.getSetting('master_server_port')
        try:
            master_server_port = int(master_server_port)  # Convert to integer
        except ValueError:
            log_message("Invalid master_server_port setting. Please provide a valid numeric port.", level=xbmc.LOGERROR)
            master_server_port = None

        if master_server_port is not None:
            kodi_boxes.append({
                "Actor": "Master",
                "IP": xbmc.getIPAddress(),
                "Encoder_URL": 'http://192.168.2.168/0.ts',
                "Status": "IDLE",
                "Proxy_Port": master_proxy_port,
                "Server_Port": master_server_port,
            })

    # Slave Kodi instance(s)
    slave_settings = [
        {
            "ip_setting": "slave_1_ip",
            "encoder_url_setting": "slave_1_encoder_url"
        },
        # Add more slave settings as needed
    ]

    for i, settings in enumerate(slave_settings, start=1):
        ip_setting = settings["ip_setting"]
        encoder_url_setting = settings["encoder_url_setting"]
        
        slave_proxy_port = find_available_port(start_port, end_port)
        if slave_proxy_port is None:
            log_message(f"No available port found for Slave {i} Kodi proxy.", level=xbmc.LOGERROR)
        else:
            kodi_boxes.append({
                "Actor": f"Slave {i}",
                "IP": ADDON.getSetting(ip_setting),
                "Encoder_URL": ADDON.getSetting(encoder_url_setting),
                "Status": "IDLE",
                "Proxy_Port": slave_proxy_port,
            })

    return kodi_boxes

KODI_BOXES = initialize_kodi_boxes()

play_request_lock = threading.Lock()

active_proxies = {}  # Dictionary to maintain active proxies per link
active_proxies_lock = threading.Lock()

proxy_clients = {}  # Dictionary to maintain active clients for each proxy
proxy_clients_lock = threading.Lock()

active_links = {} # link: kodi_box_info
active_links_lock = threading.Lock()


def get_master_kodi_box():
    for box in KODI_BOXES:
        if box["Actor"] == "Master":
            return box
    return None  # Return None if no Master box is found

def get_encoder_url_for_link(link):
    with active_links_lock:
        kodi_ip = active_links.get(link)
        if kodi_ip:
            for box in KODI_BOXES:
                if box["IP"] == kodi_ip:
                    return box["Encoder_URL"]
    log_message(f"Could not find Encoder_URL for link {link}", level=xbmc.LOGERROR)
    return None  # or some default encoder URL if you have one


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
    log_message(f"Starting playback on Kodi box with IP: {kodi_box['IP']} for {link}", level=xbmc.LOGDEBUG)
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
    log_message(f"Stopping playback on Kodi box with IP: {kodi_box['IP']}", level=xbmc.LOGDEBUG)
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
                    encoder_url = get_encoder_url_for_link(link)
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
                        stop_kodi_playback(active_links[link])
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
            self.handle_playlist_request()
        elif path == '/epg.xml':
            self.handle_epg_request()
        elif path == '/play':
            link = parse_qs(parsed_path.query).get('link', [''])[0]
            self.handle_play_request(link)
        else:
            self.send_response(404)
            self.end_headers()

    def handle_playlist_request(self):
        log_message("Received request for playlist.")
        try:
            content = self.fetch_content('http://localhost:52104/playlist.m3u8')
            transformed_content = self.transform_playlist_content(content)
            self.send_response(200)
            self.send_header('Content-type', 'application/vnd.apple.mpegurl')
            self.end_headers()
            self.wfile.write(transformed_content.encode())
        except Exception as e:
            self.handle_error(e, "Internal server error")

    def handle_epg_request(self):
        log_message("Received request for EPG.")
        try:
            content = self.fetch_content('http://localhost:52104/epg.xml')
            self.send_response(200)
            self.send_header('Content-type', 'application/xml')
            self.end_headers()
            self.wfile.write(content)
        except URLError as e:
            self.handle_error(e)

    def handle_play_request(self, parsed_path):
        log_message("Received play request.")
        with play_request_lock:
            query_params = parse_qs(parsed_path.query)
            link = query_params.get('link', [''])[0]
            self.process_play_request(link)

    def fetch_content(self, url):
        response = urlopen(url)
        return response.read().decode('utf-8')

    def transform_playlist_content(self, content):
        lines = content.split('\n')
        new_lines = []
        master_box = get_master_kodi_box()
        if not master_box:
            raise Exception("Master Kodi box not found!")
        for line in lines:
            if line.startswith('plugin://'):
                encoded_line = quote(line, safe='')
                new_url = f"http://{master_box['IP']}:{master_box['Server_Port']}/proxy?link={encoded_line}"
                new_lines.append(new_url)
            else:
                new_lines.append(line)
        return '\n'.join(new_lines)

    def process_play_request(self, link):
        log_message("Received play request.")
        with play_request_lock:
            available_kodi_box = get_available_kodi_box(link)
            if available_kodi_box:
                # If the link is already playing on a Kodi box, just redirect to its encoder URL
                encoder_url = available_kodi_box['Encoder_URL']
            else:
                # Else, initiate playback on a Kodi box and then redirect
                available_kodi_box = get_available_kodi_box(None)
                if available_kodi_box:
                    start_kodi_playback(available_kodi_box, link)
                    encoder_url = available_kodi_box['Encoder_URL']
                    with active_links_lock:
                        active_links[link] = available_kodi_box["IP"]
                else:
                    self.send_error(503, "All Kodi boxes are in use.")
                    return
            with last_accessed_links_lock:
                last_accessed_links[link] = datetime.datetime.now()
            master_box = get_master_kodi_box()
            if not master_box:
                raise Exception("Master Kodi box not found!")
            proxy_url = f"http://{master_box['IP']}:{master_box['Proxy_Port']}/proxy?link={quote(link)}"

            self.send_response(302)
            self.send_header('Location', proxy_url)
            self.end_headers()                

class MyMonitor(xbmc.Monitor):
    def __init__(self, main_httpd, proxy_servers):
        self.main_httpd = main_httpd
        self.proxy_servers = proxy_servers

    def onAbortRequested(self):
        log_message("Kodi is shutting down...")
        self.main_httpd.shutdown()
        for _, proxy_server in self.proxy_servers.items():
            proxy_server.shutdown()
        main_httpd.server_close()
        for _, proxy_server in self.proxy_servers.items():
            proxy_server.server_close()
        log_message("Servers shut down.")

MAX_WORKERS = 10  # Adjust this based on the maximum number of simultaneous threads you expect

def run():
    try:
        log_message("Starting server...")
        
        # Main server (synchronous)
        master_box = get_master_kodi_box()
        if not master_box:
            xbmcgui.Dialog().ok("Error", "Master Kodi settings not found. Addon will be disabled.")
            xbmcaddon.Addon().setSetting("enabled", "false")  # Disable the addon
            return
        
        log_message(f"Starting main server on IP {master_box['IP']} , port {master_box['Server_Port']}...")
        server_address = (master_box['IP'], master_box['Server_Port'])
        main_httpd = HTTPServer(server_address, MyHandler)

        # Create a dictionary to hold proxy servers for each KODI_BOX
        proxy_servers = {}

        for box in KODI_BOXES:
            proxy_port = box['Proxy_Port']
            log_message(f"Starting proxy server for {box['Actor']} on port {proxy_port}...")
            proxy_address = ('', proxy_port)
            proxy_httpd = ThreadingHTTPServer(proxy_address, ProxyHandler)
            proxy_servers[proxy_port] = proxy_httpd

        monitor = MyMonitor(main_httpd, proxy_servers)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            cleanup_future = executor.submit(cleanup_stale_entries)
            main_future = executor.submit(main_httpd.serve_forever)
            # Submit each proxy server to the executor
            proxy_futures = []
            for port, proxy_server in proxy_servers.items():
                future = executor.submit(proxy_server.serve_forever)
                proxy_futures.append(future)
            
            log_message("Both main server and proxy servers are now running.")

            # Monitor for Kodi shutdown or addon disable
            while not monitor.abortRequested():
                if monitor.waitForAbort(1):  # Check every 1 second if Kodi is shutting down
                    log_message("Kodi abort requested. Cleaning up...")
                    break

            # Wait for all tasks to complete
            cleanup_future.result()
            main_future.result()
            for future in proxy_futures:
                future.result()

    except Exception as e:
        log_message(f"Main execution error: {e}", level=xbmc.LOGERROR)


if __name__ == '__main__':
    log_message("Starting application...")
    run()
    log_message("Application terminated.")