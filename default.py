import xbmc, xbmcaddon, xbmcvfs, xbmcgui
import os, json, time, threading, datetime, socket
import traceback, signal
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, quote
from urllib.request import urlopen, Request
from urllib.error import URLError
from concurrent.futures import ThreadPoolExecutor

ADDON = xbmcaddon.Addon()
ENABLE_LOGGING = True # FALSE to shut off
CLEANUP_INTERVAL_SECONDS = 3600  # This will check for cleanup every hour. Adjust as needed.
MAX_LINK_IDLE_TIME_SECONDS = 3600 * 1  # Remove links that have been idle for 1 hour.

# Add an additional dictionary to track the last access time of each link.
last_accessed_links = {}
active_links_lock = threading.Lock()
shutting_down = False
assigned_ports = []

def log_message(message, level=xbmc.LOGDEBUG):
    if ENABLE_LOGGING or level == xbmc.LOGERROR:
        xbmc.log(message, level=xbmc.LOGERROR)

def signal_handler(signum, frame):
    global shutting_down
    shutting_down = True
    log_message("Received shutdown signal. Initiating graceful shutdown...")

def release_ports(ports_to_release):
    for port in ports_to_release:
        log_message(f"Release port: {port}", level=xbmc.LOGERROR)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.bind(("localhost", port))
                s.close()
        except (socket.error, OSError):
            pass

def send_jsonrpc(kodi_url, payload):
    if kodi_url == "local":
        log_message("Send JSONRPC to local kodi", level=xbmc.LOGERROR)
        try:
            command = json.dumps(payload)
            response_json = xbmc.executeJSONRPC(command)
            return json.loads(response_json)
        except Exception as e:
            error_message = f"Error sending JSONRPC to local Kodi: {str(e)}"
            log_message(error_message, level=xbmc.LOGERROR)
            # You can log additional error information or handle the error as needed.
            return None
    else:
        log_message(f"Send JSONRPC to remote kodi: {kodi_url}", level=xbmc.LOGERROR)
        try:
            request_url = f"{kodi_url}/jsonrpc"
            request_data = json.dumps(payload).encode('utf-8')
            request = Request(request_url, data=request_data, headers={'Content-Type': 'application/json'})
            response = urlopen(request)
            response_json = response.read().decode('utf-8')
            return json.loads(response_json)
        except Exception as e:
            error_message = f"Error sending JSONRPC to remote Kodi ({kodi_url}): {str(e)}"
            log_message(error_message, level=xbmc.LOGERROR)
            # You can log additional error information or handle the error as needed.
            return None


def find_available_port(start_port, end_port):
    log_message(f"looking for available port from {start_port} to {end_port}")
    for port in range(start_port, end_port + 1):
        if port not in assigned_ports:
            if is_port_available(port):
                assigned_ports.append(port)
                log_message(f"Found a good port: {port}")
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
        master_server_port = ADDON.getSetting('server_port')
        try:
            master_server_port = int(master_server_port)  # Convert to integer
        except ValueError:
            log_message("Invalid master_server_port setting. Please provide a valid numeric port.", level=xbmc.LOGERROR)
            master_server_port = None

        if master_server_port is not None:
            master_encoder_url = ADDON.getSetting('master_encoder_url')
            master_kodi_box = KodiBox("Master", xbmc.getIPAddress(), master_encoder_url, master_proxy_port, master_server_port)
            kodi_boxes.append(master_kodi_box)

    # Slave Kodi instance(s)
    for i in range(1, 4):  # Adjust the range according to the number of slave settings in your settings.xml
        ip_setting = ADDON.getSetting(f"slave_{i}_ip")
        encoder_url_setting = ADDON.getSetting(f"slave_{i}_encoder_url")
        
        # Check if the IP setting is not "0.0.0.0" before adding the slave Kodi box
        if ip_setting and ip_setting != "0.0.0.0" and encoder_url_setting:
            slave_proxy_port = find_available_port(start_port, end_port)
            if slave_proxy_port is None:
                log_message(f"No available port found for Slave {i} Kodi proxy.", level=xbmc.LOGERROR)
            else:
                log_message(f"Setup slave {ip_setting} using encoder {encoder_url_setting} with local proxy port {slave_proxy_port}")
                slave_kodi_box = KodiBox(f"Slave {i}", ip_setting, encoder_url_setting, slave_proxy_port, None)  # Create KodiBox instance
                kodi_boxes.append(slave_kodi_box)

    for box in kodi_boxes:
        if box["Status"] == "IDLE":
            box.start_socket_server()

    return kodi_boxes


KODI_BOXES = initialize_kodi_boxes()

play_request_lock = threading.Lock()

active_proxies = {}  # Dictionary to maintain active proxies per link
active_proxies_lock = threading.Lock()

active_links = {} # link: kodi_box_info
active_links_lock = threading.Lock()


def get_master_kodi_box():
    for box in KODI_BOXES:
        if box.actor == "Master":
            return box
    return None

def get_encoder_url_for_link(link, headers={}):
    log_message(f"Lookup encoder url for link {link}", level=xbmc.LOGERROR)
    with active_links_lock:
        kodi_ip = active_links.get(link)
        if kodi_ip:
            for box in KODI_BOXES:
                if box.ip == kodi_ip:
                    encoder_url = box.encoder_url
                    with urlopen(Request(encoder_url, headers=headers)) as response:  # Ensure the connection is closed
                        return response
    log_message(f"Could not find Encoder_URL for link {link}", level=xbmc.LOGERROR)
    return None  # or some default encoder URL if you have one


def get_available_kodi_box(link):
    log_message(f"Look for available kodi box with link {link}", level=xbmc.LOGERROR)
    # Find an available Kodi box
    for box in KODI_BOXES:
        if box.status == "IDLE":
            box.mark_playing()  # Mark the box as PLAYING using the method
            if link:
                active_links[link] = box.ip
            log_message(f"Found available kodi box with ip {box.ip}", level=xbmc.LOGERROR)
            return box
    log_message(f"Not Found available kodi box", level=xbmc.LOGERROR)
    return None


def stop_kodi_playback(kodi_box):
    # Stop playback on the specified Kodi box
    log_message(f"Stopping playback on box {kodi_box}", level=xbmc.LOGERROR)
    kodi_box.stop_playback()
    with active_links_lock:
        for link, box_ip in active_links.items():
            if box_ip == kodi_box.ip:
                del active_links[link]
                break
    kodi_box.mark_idle()

def cleanup_stale_entries():
    global active_proxies, active_links, last_accessed_links
    
    while True:
        time.sleep(CLEANUP_INTERVAL_SECONDS)
        
        log_message(f"Running cleanup process.....", level=xbmc.LOGERROR)

        # Find links that haven't been accessed recently.
        stale_links = set()
        current_time = datetime.datetime.now()

        with last_accessed_links_lock:
            for link, last_access_time in last_accessed_links.items():
                if (current_time - last_access_time).total_seconds() > MAX_LINK_IDLE_TIME_SECONDS:
                    stale_links.add(link)

            # Remove the stale links from our tracking
            for link in stale_links:
                log_message(f"Dropping stale link {link}", level=xbmc.LOGERROR)
                del last_accessed_links[link]

        # Now, clean up resources associated with stale links
        with active_proxies_lock:
            for link in stale_links:
                if link in active_proxies:
                    active_proxies[link]['encoder_connection'].close()
                    log_message(f"Closing stale proxy {active_proxies[link]['encoder_connection']}", level=xbmc.LOGERROR)
                    del active_proxies[link]

        with active_links_lock:
            for link in stale_links:
                if link in active_links:
                    log_message(f"Closing stale active links {active_links[link]}", level=xbmc.LOGERROR)
                    del active_links[link]

def handle_client(client_socket, target_host, target_port):
    try:
        with client_socket:
            request_data = client_socket.recv(1024)
            if not request_data:
                return

            with socket.create_connection((target_host, target_port)) as server_socket:
                server_socket.send(request_data)
                while True:
                    response_data = server_socket.recv(4096)
                    if not response_data:
                        break
                    client_socket.send(response_data)
    except BrokenPipeError:
        log_message("Client closed the connection before the response could be sent.")
    except Exception as e:
        log_message(f"Error while handling client: {str(e)}", level=xbmc.LOGERROR)


shutdown_socket_server_event = threading.Event()


def start_socket_server(proxy_port, target_host, target_port):
    if shutdown_socket_server_event.is_set():
        return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("", proxy_port))
    server_socket.listen(5)

    log_message(f"Raw socket server listening on port {proxy_port}")

    while not shutdown_socket_server_event.is_set():
        client_socket, addr = server_socket.accept()
        log_message(f"Accepted connection from {addr[0]}:{addr[1]}")
        threading.Thread(target=handle_client, args=(client_socket, target_host, target_port)).start()

    server_socket.close()





class MyHandler(BaseHTTPRequestHandler):

    def handle_error(self, e):
        log_message(f"HTTP request handling error: {e}", level=xbmc.LOGERROR)
        self.send_response(500)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(str(e).encode())

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
            self.handle_error(e)

    def handle_epg_request(self):
        log_message("Received request for EPG.")
        try:
            content = self.fetch_content('http://localhost:52104/epg.xml')
            content_bytes = content.encode('utf-8')  # Encode the content as bytes
    
            self.send_response(200)
            self.send_header('Content-type', 'application/xml')
            self.end_headers()
            self.wfile.write(content_bytes)  # Write the encoded content as bytes
        except URLError as e:
            self.handle_error(e)

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
                new_url = f"http://{master_box['IP']}:{master_box['Server_Port']}/play?link={encoded_line}"
                new_lines.append(new_url)
            else:
                new_lines.append(line)
        return '\n'.join(new_lines)

    def handle_play_request(self, link):
        log_message("Received play request.")
        with play_request_lock:
            available_kodi_box = get_available_kodi_box(link)
            if available_kodi_box:
                # If the link is already playing on a Kodi box, just redirect to its encoder URL
                log_message(f"Found already playing on a Kodi box, directing to {available_kodi_box['Encoder_URL']}", level=xbmc.LOGERROR)
                encoder_url = available_kodi_box['Encoder_URL']
            else:
                # Else, initiate playback on a Kodi box and then redirect
                available_kodi_box = get_available_kodi_box(None)
                if available_kodi_box:
                    available_kodi_box.start_playback(link)
                    log_message(f"Started a new box, redirecting to {available_kodi_box.encoder_url}", level=xbmc.LOGERROR)
                    encoder_url = available_kodi_box.encoder_url
                    with active_links_lock:
                        active_links[link] = available_kodi_box.ip
                else:
                    self.send_error(503, "All Kodi boxes are in use.")
                    return
            with last_accessed_links_lock:
                last_accessed_links[link] = datetime.datetime.now()
            master_box = get_master_kodi_box()
            if not master_box:
                raise Exception("Master Kodi box not found!")
            proxy_url = f"http://{master_box.ip}:{master_box.proxy_port}/proxy?link={quote(link)}"

            self.send_response(302)
            self.send_header('Location', proxy_url)
            self.end_headers()                

class KodiBox:
    def __init__(self, actor, ip, encoder_url, proxy_port, server_port):
        self.actor = actor
        self.ip = ip
        self.encoder_url = encoder_url
        self.proxy_port = proxy_port
        self.server_port = server_port
        self.status = "IDLE"
        self.socket_server_thread = None

    def start_socket_server(self):
        if hasattr(self, 'socket_server_thread') and self.socket_server_thread.is_alive():
            log_message("Socket server is already running.", level=xbmc.LOGWARNING)
            return

        self.socket_server_thread = threading.Thread(target=start_socket_server, args=(self.proxy_port, self.ip, self.server_port))
        self.socket_server_thread.start()

    def stop_socket_server(self):
        global shutdown_socket_server_event
        shutdown_socket_server_event.set()

        if self.socket_server_thread and self.socket_server_thread.is_alive():
            self.socket_server_thread.join()

    def start_playback(self, link):
        # Start playback on the Kodi box
        log_message(f"Starting playback on Kodi box {self.actor} with IP: {self.ip} for {link}", level=xbmc.LOGDEBUG)
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
        kodi_url = "local" if self.actor == "Master" else f"http://{self.ip}:8080"
        response_json = send_jsonrpc(kodi_url, payload)
        if response_json and 'error' in response_json:
            log_message(f"Error in JSON-RPC response: {response_json['error']}", level=xbmc.LOGERROR)

    def stop_playback(self):
        # Stop playback on the Kodi box
        log_message(f"Stopping playback on Kodi box {self.actor} with IP: {self.ip}", level=xbmc.LOGDEBUG)
        payload = {
            "jsonrpc": "2.0",
            "method": "Player.Stop",
            "params": {
                "playerid": 1
            },
            "id": 1
        }
        kodi_url = "local" if self.actor == "Master" else f"http://{self.ip}:8080"
        response_json = send_jsonrpc(kodi_url, payload)
        if response_json and 'error' in response_json:
            log_message(f"Error in JSON-RPC response: {response_json['error']}", level=xbmc.LOGERROR)

    def mark_idle(self):
        self.status = "IDLE"
        self.start_socket_server()

    def mark_playing(self):
        self.status = "PLAYING"
        self.stop_socket_server()

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
            xbmcgui.Dialog().ok("Error", "Master Kodi settings not found or set correctly. Addon will be disabled.")
            xbmcaddon.Addon().setSetting("enabled", "false")  # Disable the addon
            return
        
        log_message(f"Starting main server on IP {master_box['IP']} , port {master_box['Server_Port']}...")
        server_address = (master_box['IP'], master_box['Server_Port'])
        main_httpd = HTTPServer(server_address, MyHandler)
        main_httpd.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        monitor = MyMonitor(main_httpd)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            cleanup_future = executor.submit(cleanup_stale_entries)
            main_future = executor.submit(main_httpd.serve_forever)
            
            log_message("Main server is now running.")

            # Monitor for Kodi shutdown or addon disable
            while not monitor.abortRequested() and not shutting_down:
                if monitor.waitForAbort(1) or shutting_down:
                    log_message("Kodi abort requested or shutdown signal received. Cleaning up...")
                    break

            # Wait for all tasks to complete
            cleanup_future.result()
            main_future.result()

    except Exception as e:
        log_message(f"Main execution error: {e}", level=xbmc.LOGERROR)

    finally:
        log_message("Initiating graceful shutdown sequence...")

        global shutdown_socket_server_event
        shutdown_socket_server_event.set()

        if cleanup_future:
            cleanup_future.cancel()
        if main_future:
            main_future.cancel()

        release_ports([box['Proxy_Port'] for box in KODI_BOXES] + [master_box['Server_Port']])
        log_message("Graceful shutdown completed.")


if __name__ == '__main__':
    # Register signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    log_message("Starting application...")
    run()
    log_message("Application terminated.")