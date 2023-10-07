import xbmc, xbmcaddon, xbmcvfs, xbmcgui
import os, json, time, threading, datetime, socket
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, quote, unquote
from urllib.request import urlopen, Request
from urllib.error import URLError
from concurrent.futures import ThreadPoolExecutor

ADDON = xbmcaddon.Addon()
ENABLE_LOGGING = True # FALSE to shut off
CLEANUP_INTERVAL_SECONDS = 3600  # This will check for cleanup every hour. Adjust as needed.
MAX_LINK_IDLE_TIME_SECONDS = 3600 * 1  # Remove links that have been idle for 1 hour.
PROXY_SERVERS = []
ACTIVE_SOCKETS = {}

# Add an additional dictionary to track the last access time of each link.
last_accessed_links = {}
active_links_lock = threading.Lock()
assigned_ports = []

def log_message(message, level=xbmc.LOGDEBUG):
    if ENABLE_LOGGING or level == xbmc.LOGERROR:
        xbmc.log(f"IPTV_Encoder_Proxy: {message}", level=xbmc.LOGERROR)


def release_ports(ports_to_release):
    for port in ports_to_release:
        log_message(f"Attempting to release port: {port}...", level=xbmc.LOGERROR)
        if port in ACTIVE_SOCKETS:
            ACTIVE_SOCKETS[port].close()  # Close the socket.
            del ACTIVE_SOCKETS[port]      # Remove it from the dictionary.
            log_message(f"Port {port} released.", level=xbmc.LOGDEBUG)
        else:
            log_message(f"Port {port} not found in active sockets.", level=xbmc.LOGDEBUG)

def send_jsonrpc(kodi_url, payload=None):
    if payload is None:
        payload = {}

    if kodi_url == "local":
        log_message("Send JSONRPC to local kodi", level=xbmc.LOGERROR)
        try:
            command = json.dumps(payload)
            response_json = xbmc.executeJSONRPC(command)
            log_message(f"Received JSON-RPC response: {response_json}", level=xbmc.LOGDEBUG)
            return json.loads(response_json)
        except Exception as e:
            log_message(f"Error sending JSON-RPC to local Kodi: {str(e)}\n{traceback.format_exc()}", level=xbmc.LOGERROR)
            # You can log additional error information or handle the error as needed.
            return None
    else:
        log_message(f"Send JSONRPC to remote kodi: {kodi_url}", level=xbmc.LOGERROR)
        try:
            request_url = f"{kodi_url}/jsonrpc"
            request_data = json.dumps(payload).encode('utf-8')
            request_headers = {'Content-Type': 'application/json'}
            log_message(f"Sending HTTP request to {request_url} with headers: {request_headers} and data: {request_data}", level=xbmc.LOGDEBUG)
            request = Request(request_url, data=request_data, headers={'Content-Type': 'application/json'})
            response = urlopen(request)
            response_json = response.read().decode('utf-8')
            return json.loads(response_json)
        except Exception as e:
            log_message(f"Error sending JSON-RPC to remote Kodi '{kodi_url}' : {str(e)}\n{traceback.format_exc()}", level=xbmc.LOGERROR)
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

shutdown_socket_server_event = threading.Event()


def start_socket_server(proxy_port, target_host, target_port):
    log_message(f"Attempting to start socket server on port {proxy_port}, target_host {target_host}, target_port {target_port}...", level=xbmc.LOGERROR)
    global PROXY_SERVERS
    if shutdown_socket_server_event.is_set():
        log_message("shutdown_socket_server_event.is_set is true", level=xbmc.LOGERROR)
        return

    def socket_server_loop():
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("0.0.0.0", proxy_port))
        log_message(f"Server socket bound to Port: {proxy_port}", level=xbmc.LOGDEBUG)
        ACTIVE_SOCKETS[proxy_port] = server_socket
        server_socket.listen(5)
        log_message(f"Append {proxy_port} to PROXY_SERVERS", level=xbmc.LOGDEBUG)
        PROXY_SERVERS.append(proxy_port)
        log_message(f"Raw socket server initialized and listening on port {proxy_port}", level=xbmc.LOGDEBUG)

        while not shutdown_socket_server_event.is_set():
            client_socket, addr = server_socket.accept()
            log_message(f"Accepted proxy connection from {addr[0]}:{addr[1]}", level=xbmc.LOGDEBUG)
            threading.Thread(target=handle_client, args=(client_socket, target_host, target_port)).start()

    threading.Thread(target=socket_server_loop).start()

class KodiBox:
    def __init__(self, actor, ip, encoder_url, proxy_port, server_port):
        self.actor = actor
        self.ip = ip
        self.encoder_url = encoder_url
        self.proxy_port = proxy_port
        self.server_port = server_port
        self.status = "IDLE"
        self.socket_server_thread = None

    def _send_jsonrpc_command(self, method, params):
        log_message(f"Sending JSON-RPC command '{method}' with payload: {json.dumps(params)} to {self.ip}", level=xbmc.LOGDEBUG)
        log_message(f"{method} on Kodi box {self.actor} with IP: {self.ip}", level=xbmc.LOGDEBUG)
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        }
        kodi_url = "local" if self.actor == "Master" else f"http://{self.ip}:8080"
        log_message(f"Interacting with Kodi box '{self.actor}' at {kodi_url}", level=xbmc.LOGDEBUG)
        response_json = send_jsonrpc(kodi_url, payload)
        if response_json and 'error' in response_json:
            log_message(f"Error in JSON-RPC response: {response_json['error']}", level=xbmc.LOGERROR)

    def start_playback(self, link):
        log_message(f"Starting playback of link {link} on Kodi box with IP {self.ip}", level=xbmc.LOGERROR)
        # Start playback on the Kodi box
        decoded_link = unquote(link)
        self._send_jsonrpc_command("Player.Open", {"item": {"file": decoded_link}})

    def stop_playback(self):
        log_message(f"Stopping playback on Kodi box with IP {self.ip}", level=xbmc.LOGERROR)
        # Stop playback on the Kodi box
        self._send_jsonrpc_command("Player.Stop", {"playerid": 1})

    def stop_socket_server(self):
        global shutdown_socket_server_event
        shutdown_socket_server_event.set()
        if self.socket_server_thread and self.socket_server_thread.is_alive():
            self.socket_server_thread.join()

    def mark_idle(self):
        self.status = "IDLE"
        # Call the module-level start_socket_server function
        start_socket_server(self.proxy_port, self.ip, self.server_port)

    def mark_playing(self):
        self.status = "PLAYING"
        self.stop_socket_server()


def initialize_kodi_boxes():
    log_message("Initializing Kodi boxes...", level=xbmc.LOGERROR)
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
        log_message(f"Initialized Kodi box with IP: {box.ip}, Proxy Port: {box.proxy_port}, Server port: {box.server_port}", level=xbmc.LOGDEBUG)
        if box.status == "IDLE":
            start_socket_server(box.proxy_port, box.ip, box.server_port)

    log_message("Initialization of Kodi boxes completed.", level=xbmc.LOGERROR)
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

    # Check if link is already playing on a Kodi box
    if link in active_links:
        log_message(f"link : {link} found in active_links")
        for box in KODI_BOXES:
            log_message(f"Checking Kodi box with ip {box.ip}")
            if box.ip == active_links[link]:
                log_message(f"Link already playing on Kodi box with ip {box.ip}", level=xbmc.LOGERROR)
                return box
            else:
                log_message(f"No match found for box with ip {box.ip}")
    else:
        log_message(f"link : {link} NOT found in active_links")

    log_message("Check for IDLE boxes")
    # Find an available IDLE Kodi box
    for box in KODI_BOXES:
        log_message(f"Checking Kodi box with ip {box.ip}")
        if box.status == "IDLE":
            log_message(f"Kodi box with ip {box.ip} is IDLE")
            box.mark_playing()  # Mark the box as PLAYING
            if link is not None and link != "":
                log_message(f"Assign active_links with link {link} to kodi IP {box.ip}")
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
                active_links.pop(link, None)
                break
    kodi_box.mark_idle()

def cleanup_stale_entries():
    log_message("Cleanup stale entries process initiated...", level=xbmc.LOGERROR)
    global active_proxies, active_links, last_accessed_links
    
    while True:
        time.sleep(CLEANUP_INTERVAL_SECONDS)
        
        log_message(f"Running cleanup process.....", level=xbmc.LOGERROR)

        # Find links that haven't been accessed recently.
        stale_links = set()
        current_time = datetime.datetime.now()

        with active_links_lock:
            for link, last_access_time in last_accessed_links.items():
                if (current_time - last_access_time).total_seconds() > MAX_LINK_IDLE_TIME_SECONDS:
                    log_message(f"Found link to cleanup {link}", level=xbmc.LOGERROR)
                    stale_links.add(link)

            # Remove the stale links from our tracking
            for link in stale_links:
                log_message(f"Dropping stale link {link}", level=xbmc.LOGERROR)
                last_accessed_links.pop(link, None)

        # Now, clean up resources associated with stale links
        with active_proxies_lock:
            for link in stale_links:
                log_message(f"Scan for active proxy link cleanup {link}", level=xbmc.LOGERROR)
                if link in active_proxies:
                    log_message(f"Closing stale proxy for link: {link}", level=xbmc.LOGERROR)
                    active_proxies[link]['encoder_connection'].close()
                    log_message(f"Closing stale proxy {active_proxies[link]['encoder_connection']}", level=xbmc.LOGERROR)
                    active_proxies.pop(link, None)

        with active_links_lock:
            for link in stale_links:
                log_message(f"Scan for active link cleanup {link}", level=xbmc.LOGERROR)
                if link in active_links:
                    log_message(f"Closing stale active links {active_links[link]}", level=xbmc.LOGERROR)
                    active_links.pop(link, None)

def is_kodi_box_playing(kodi_box, link):
    with active_links_lock:
        log_message(f"Check if kodi box {kodi_box} is playing {link}", level=xbmc.LOGERROR)
        if link in active_links and active_links[link] == kodi_box.ip:
            log_message(f"Found link {link} playing on {kodi_box.ip}", level=xbmc.LOGERROR)
            return True
    log_message("Not finding any kodi box playing link {link}", level=xbmc.LOGERROR)
    return False


def handle_client(client_socket, target_host, target_port):
    log_message(f"Begin handling client request on proxy port {target_port}", level=xbmc.LOGDEBUG)
    try:
        # Determine the Kodi box this request pertains to based on the port
        kodi_box = next((box for box in KODI_BOXES if box.proxy_port == target_port), None)
        
        if not kodi_box:
            log_message(f"No Kodi box found for port {target_port}", level=xbmc.LOGERROR)
            return

        encoder_url = kodi_box.encoder_url
        
        # Parse the encoder URL to determine its host and port
        parsed_encoder_url = urlparse(encoder_url)
        encoder_host = parsed_encoder_url.hostname
        encoder_port = parsed_encoder_url.port if parsed_encoder_url.port else 80  # Default to port 80 if not specified

        # Connect to the encoder and stream its content back to the client
        with socket.create_connection((encoder_host, encoder_port)) as encoder_socket:
            
            # 1. Capture the request data from the client
            request_data = client_socket.recv(4096)

            # 2. Forward the captured request data to the encoder
            encoder_socket.sendall(request_data)
            
            # Stream the encoder's response back to the client
            while True:
                response_data = encoder_socket.recv(4096)
                if not response_data:
                    break
                client_socket.send(response_data)

    except Exception as e:
        log_message(f"Error while handling client: {str(e)}", level=xbmc.LOGERROR)




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
            self.handle_error(f"Unexpected error: {e}")

    def fetch_content(self, url):
        response = urlopen(url)
        return response.read().decode('utf-8')

    def transform_playlist_content(self, content):
        lines = content.split('\n')
        new_lines = []
        master_kodi_box = get_master_kodi_box()
        if not master_kodi_box:
            raise Exception("Master Kodi box not found!")
        for line in lines:
            if line.startswith('plugin://'):
                encoded_line = quote(line, safe='')
                new_url = f"http://{master_kodi_box.ip}:{master_kodi_box.server_port}/play?link={encoded_line}"
                new_lines.append(new_url)
            else:
                new_lines.append(line)
        return '\n'.join(new_lines)

    def handle_play_request(self, link):
        log_message("Received play request.")
        with play_request_lock:
            available_kodi_box = get_available_kodi_box(link)
            if available_kodi_box:
                log_message(f"Link already playing on a Kodi box, directing to {available_kodi_box.encoder_url}", level=xbmc.LOGERROR)
                encoder_url_path = urlparse(available_kodi_box.encoder_url).path
            else:
                available_kodi_box = get_available_kodi_box(None)
                if available_kodi_box:
                    available_kodi_box.start_playback(link)
                    log_message(f"Started playback on a new box, redirecting to {available_kodi_box.encoder_url}", level=xbmc.LOGERROR)
                    encoder_url_path = urlparse(available_kodi_box.encoder_url).path
                    with active_links_lock:
                        active_links[link] = available_kodi_box.ip
                else:
                    self.send_error(503, "All Kodi boxes are in use.")
                    return
    
            with active_links_lock:
                last_accessed_links[link] = datetime.datetime.now()
            master_kodi_box = get_master_kodi_box()
            if not master_kodi_box:
                raise Exception("Master Kodi box not found!")
            encoder_path = urlparse(available_kodi_box.encoder_url).path
            proxy_url = f"http://{master_kodi_box.ip}:{master_kodi_box.proxy_port}{encoder_path}"
            
            log_message(f"Sending client to proxy URL: {proxy_url}", level=xbmc.LOGERROR)
    
            self.send_response(302)
            self.send_header('Location', proxy_url)
            self.end_headers()           

class MyMonitor(xbmc.Monitor):
    def __init__(self, main_httpd):
        self.main_httpd = main_httpd

    def onAbortRequested(self):
        log_message("Kodi is shutting down...")
        self.main_httpd.shutdown()
        
        for proxy_server in PROXY_SERVERS:
            log_message(f"Shutting down proxy server on port {proxy_server.getsockname()[1]}", level=xbmc.LOGERROR)
            proxy_server.close()  # Shut down the proxy server
        
        self.main_httpd.server_close()
        log_message("Servers shut down.")

MAX_WORKERS = 10  # Adjust this based on the maximum number of simultaneous threads you expect

def run():
    cleanup_future = None
    main_future = None
    try:
        log_message("Starting server...")
        
        # Main server (synchronous)
        master_kodi_box = get_master_kodi_box()
        if not master_kodi_box:
            xbmcgui.Dialog().ok("Error", "Master Kodi settings not found or set correctly. Addon will be disabled.")
            xbmcaddon.Addon().setSetting("enabled", "false")  # Disable the addon
            return
        
        log_message(f"Starting main server on IP {master_kodi_box.ip} , port {master_kodi_box.server_port}...")
        server_address = (master_kodi_box.ip, master_kodi_box.server_port)
        main_httpd = HTTPServer(server_address, MyHandler)
        main_httpd.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        monitor = MyMonitor(main_httpd)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            cleanup_future = executor.submit(cleanup_stale_entries)
            main_future = executor.submit(main_httpd.serve_forever)
            
            log_message("Main server is now running.")

            # Monitor for Kodi shutdown or addon disable
            while not monitor.abortRequested():
                if monitor.waitForAbort(1):
                    log_message("Shutdown signal received from Kodi.", level=xbmc.LOGERROR)
                    break

            log_message(f"Active threads before shutdown: {threading.active_count()}", level=xbmc.LOGERROR)

            # Wait for all tasks to complete
            try:
                cleanup_future.result(timeout=1)  # wait forv1 seconds
                main_future.result(timeout=1)
            except concurrent.futures.TimeoutError:
                log_message("Future task took too long to complete.", level=xbmc.LOGERROR)

    except Exception as e:
        log_message(f"Main execution error: {e}", level=xbmc.LOGERROR)

    finally:
        try:
            log_message("Initiating graceful shutdown sequence...")
    
            global shutdown_socket_server_event
            log_message("Setting shutdown event for socket servers...")
            shutdown_socket_server_event.set()
            log_message("Shutdown event for socket servers set.")

    
            # Handle cleanup future
            if cleanup_future:
                log_message("Attempting to cancel cleanup_future...")
                cleanup_future.cancel()
                log_message("cleanup_future cancelled.")
    
            # Handle main future
            if main_future:
                log_message("Attempting to cancel main_future...")
                main_future.cancel()
                log_message("main_future cancelled.")

            log_message("Shutting down executor...")
            executor.shutdown(wait=False)
            log_message("Executor shutdown completed.")

            log_message("Releasing ports...")
            release_ports([box.proxy_port for box in KODI_BOXES] + [master_kodi_box.server_port])
            log_message("Ports released successfully.")
            log_message("Graceful shutdown completed.")
        except Exception as e:
            log_message(f"Error during graceful shutdown: {e}", level=xbmc.LOGERROR)


if __name__ == '__main__':
    log_message("Starting application...")
    run()
    log_message("Application terminated.")