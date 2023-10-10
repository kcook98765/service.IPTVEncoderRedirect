import xbmc, xbmcaddon
import http.server
import socketserver
from urllib.request import urlopen, quote, urlparse, Request, urljoin
from urllib.error import URLError
import urllib.parse
import time
import threading
import traceback
import json
import socket
from base64 import b64encode

ADDON = xbmcaddon.Addon()
ENABLE_LOGGING = True # FALSE to shut off
assigned_ports = []
start_port, end_port = 49152, 65535
active_proxies = {}
SERVER_PORT = ADDON.getSettingInt('server_port')

class ProxyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):

    def do_GET(self):
#        log_message("ProxyHTTPRequestHandler - Starting GET request handling.")
        # Update last activity time for the proxy instance
        self.server.last_activity = time.time()
#        log_message(f"ProxyHTTPRequestHandler - Path of this request: {self.path}")

        if self.path.endswith('.m3u8'):
            m3u8_url = urljoin(self.server.m3u8_url, self.path)
#            log_message(f"Streaming .m3u8 content from URL: {m3u8_url}")
            
            try:
                with urlopen(m3u8_url) as response:
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/vnd.apple.mpegurl')
                    self.end_headers()
                    
                    # Stream data in chunks
                    chunk_size = 1024  # 1KB. Adjust based on your preference
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break  # EOF
                        self.wfile.write(chunk)
                        self.wfile.flush()  # Ensure the chunk is sent immediately
            except Exception as e:
                self.server.status = "ERROR"
#                log_message(f"Failed to stream .m3u8 data from URL: {m3u8_url}. Error: {e}", level=xbmc.LOGERROR)
                self.send_response(500)
                self.end_headers()
        else:
            # Redirect to the encoder URL for all other requests
            redirect_url = urljoin(self.server.m3u8_url, self.path)
#            log_message(f"Redirecting to URL: {redirect_url}")
            self.send_response(302)  # HTTP 302 is for redirect
            self.send_header('Location', redirect_url)
            self.end_headers()

    def log_message(self, format, *args):
        pass

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    last_activity = time.time()
    daemon_threads = True

    def __init__(self, server_address, handler, m3u8_url, epg_url, link, kodi_ip, name):
        log_message("Initializing ThreadedTCPServer.")
        super().__init__(server_address, handler)
        self.m3u8_url = m3u8_url
        self.epg_url = epg_url
        self.link = link
        self.kodi_ip = kodi_ip
        self.name = name

    def start_monitoring(self):
        def monitor():
            while True:
                time_since_last_activity = time.time() - self.last_activity
#                log_message(f"Time elapsed since last activity for Kodi IP {self.kodi_ip}: {time_since_last_activity} seconds.", level=xbmc.LOGDEBUG)
                current_status = active_proxies[self.server_address[1]]['status']
                if time_since_last_activity > 15 and current_status != "IDLE":
                    # Stop Kodi playback
                    log_message(f"Stopping Kodi playback for IP {self.kodi_ip} due to inactivity.")
                    kodi = KodiJsonRPC(self.kodi_ip)
                    kodi.stop_play()
                    active_proxies[self.server_address[1]]['status'] = "IDLE"
                    active_proxies[self.server_address[1]]['link'] = ""
                    log_message(f"Proxy for Kodi IP {self.kodi_ip} set to IDLE after 15 Sec inactivity.", level=xbmc.LOGDEBUG)
                time.sleep(10)  # Check every 10 seconds
#                log_message(f"Monitoring thread checked for Kodi IP {self.kodi_ip}, status: {active_proxies[self.server_address[1]]['status']}")
        
        log_message("Starting proxy monitoring thread.")
        monitoring_thread = threading.Thread(target=monitor)
        monitoring_thread.daemon = True  # So the monitoring thread exits when the main program does
        monitoring_thread.start()

class KodiJsonRPC:
    def __init__(self, kodi_ip='localhost', kodi_port=8080, username='kodi', password='kodi'):
        log_message(f"Initializing KodiJsonRPC for IP: {kodi_ip}, port: {kodi_port}")
        self.base_url = f"http://{kodi_ip}:{kodi_port}/jsonrpc"
        self.kodi_ip = kodi_ip
        self.auth = b64encode(f"{username}:{password}".encode()).decode('utf-8')

    def is_busy_dialog_active(self):
        log_message("Checking if busy dialog is active.")
        params = {
            "booleans": ["Window.IsActive(busydialog)"]
        }
        response = self._send_command("XBMC.GetInfoBooleans", params)
        return response.get('result', {}).get('Window.IsActive(busydialog)', False)

    def close_busy_dialog(self):
        # If you determine the busy dialog is open, you might want to send a "back" 
        # action to close it. Note that doing so might have other unintended effects 
        # depending on what's causing the busy dialog.
        log_message("Sending back action to close busy dialog.")
        self._send_command("Input.Back")

    def safe_play_path(self, path):
        if self.is_busy_dialog_active():
            log_message("Busy dialog is active. Attempting to close.")
            self.close_busy_dialog()
            time.sleep(2)  # Give Kodi a moment to process the 'back' action.
        self.play_path(path)

    def _send_command(self, method, params={}):
        log_message(f"Sending command {method} with parameters: {params}")
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        }
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {self.auth}"
        }

        req = Request(self.base_url, data=json.dumps(payload).encode(), headers=headers)
        with urlopen(req) as response:
            result = json.loads(response.read())
            log_message(f"Received response from Kodi ({self.base_url}): {result}")
            return result

    def play_path(self, path):
        decoded_path = urllib.parse.unquote(path)
        log_message(f"Attempting to play path: {decoded_path}")
        params = {
            "item": {
                "file": decoded_path
            }
        }
        return self._send_command("Player.Open", params)

    def stop_play(self):
        log_message("Attempting to stop playback.")
        params = {
            "playerid": 1
        }
        return self._send_command("Player.Stop", params)

    def get_playback_status(self):
        log_message("Checking playback status.")
        # Check speed property to see if something is playing
        params = {
            "playerid": 1,
            "properties": ["speed"]
        }
        response = self._send_command("Player.GetProperties", params)
        return response.get('result', {}).get('speed', 0)

    def reboot(self):
        log_message("Sending reboot command.")
        self._send_command("System.Reboot")

class MainHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    # This handler will process the incoming requests on port SERVER_PORT
    
    def do_GET(self):
        log_message(f"MainHTTPRequestHandler - Handling GET request for path: {self.path}")
        parsed_path = urlparse(self.path)

        if parsed_path.path.endswith('.m3u8'):
            log_message(f"Master m3u8, processing")
            if self.handle_playlist_request():
                return

        elif parsed_path.path.endswith('epg.xml'):
            log_message(f"Master EPG, processing")
            if self.handle_epg_request():
                return

        elif parsed_path.path == "/play":
            link = parsed_path.query.split("link=")[-1]
            
            log_message(f"MainHTTPRequestHandler - Handling GET request for link: {link}")
        
            # Search for a proxy playing this link
            proxy_port = None
            kodi_ip = None
            for port, details in active_proxies.items():
                if "Encoder" in details['name'] and details['link'] == link and details['status'] == "RUNNING":
                    log_message(f"MainHTTPRequestHandler - found active proxy for: {link} on port {port}")
                    proxy_port = port
                    kodi_ip = details['kodi_ip']
                    break
        
            # If not found, choose an available proxy and update its link and status
            if proxy_port is None:
                for port, details in active_proxies.items():
                    if "Encoder" in details['name'] and details['status'] != "RUNNING":
                        log_message(f"MainHTTPRequestHandler - found inactive proxy for: {link} on port {port}")
                        proxy_port = port
                        kodi_ip = details['kodi_ip']
                        details['link'] = link
                        details['status'] = "RUNNING"
                        # Send the "play" command to the associated Kodi
                        log_message(f"MainHTTPRequestHandler - sending kodi {details['kodi_ip']} a play command for {link} on port {port}")
                        kodi_rpc = KodiJsonRPC(kodi_ip=details['kodi_ip'])
                        kodi_rpc.safe_play_path(link)
                        break
        
            if proxy_port:
                encoder_url = active_proxies[proxy_port]['m3u8_url']  # or whatever attribute is needed
                # Redirect to encoder_url and initiate Kodi playback
                proxy_url = f"http://192.168.2.9:{proxy_port}/0.m3u8"
                log_message(f"MainHTTPRequestHandler - redirect /play request to {proxy_url}")
                self.send_response(302)
                self.send_header('Location', proxy_url)
                self.end_headers()
        
            else:
                self.send_response(503)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"All encoders busy!")
                log_message("All encoders busy, returning 503.")
        
        elif parsed_path.path == "/status":
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            cleaned_data = {key: make_serializable(val) for key, val in active_proxies.items()}
            self.wfile.write(json.dumps(cleaned_data).encode('utf-8'))
        
        else:
            self.send_response(404)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Not Found")
            log_message("Received unknown endpoint request, returning 404.")

    def handle_playlist_request(self):
        log_message("Received request for playlist.")
        try:
            content = self.fetch_content('http://localhost:52104/playlist.m3u8')
            transformed_content = self.transform_playlist_content(content)
            self.send_response(200)
            self.send_header('Content-type', 'application/vnd.apple.mpegurl')
            self.end_headers()
            self.wfile.write(transformed_content.encode())
            return True  # Request handled successfully
        except Exception as e:
            self.handle_error(e)
            return False  # Request handling failed

    def handle_epg_request(self):
        log_message("Received request for EPG.")
        try:
            content = self.fetch_content('http://localhost:52104/epg.xml')
            content_bytes = content.encode('utf-8')  # Encode the content as bytes
    
            self.send_response(200)
            self.send_header('Content-type', 'application/xml')
            self.end_headers()
            self.wfile.write(content_bytes)  # Write the encoded content as bytes
            return True  # Request handled successfully
        except URLError as e:
            self.handle_error(f"Unexpected error: {e}")
            return False  # Request handling failed

    def handle_error(self, e):
        log_message(f"HTTP request handling error: {e}\n{traceback.format_exc()}", level=xbmc.LOGERROR)
        try:
            self.send_response(500)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(str(e).encode())
        except BrokenPipeError:
            log_message("Broken pipe error while handling another error.", level=xbmc.LOGERROR)

    def transform_playlist_content(self, content):
        lines = content.split('\n')
        new_lines = []
        for line in lines:
            if line.startswith('plugin://'):
                encoded_line = quote(line, safe='')
                new_url = f"http://{xbmc.getIPAddress()}:{SERVER_PORT}/play?link={encoded_line}"
                new_lines.append(new_url)
            else:
                new_lines.append(line)
        return '\n'.join(new_lines)

    def fetch_content(self, url):
        response = urlopen(url)
        return response.read().decode('utf-8')

    def log_message(self, format, *args):
        pass

class GracefulKodiMonitor(xbmc.Monitor):
    def onAbortRequested(self):
        log_message("Shutdown requested by Kodi. Starting cleanup process...", level=xbmc.LOGNOTICE)
        cleanup()

def make_serializable(data_dict):
    new_dict = {}
    for key, value in data_dict.items():
        if isinstance(value, threading.Thread):
            # Convert the thread object into a string representation (e.g., its name)
            new_dict[key] = str(value)
        else:
            new_dict[key] = value
    return new_dict


def wait_for_addon(addon_id, timeout=120):
    log_message(f"Check for addon {addon_id} to see if it is running", level=xbmc.LOGDEBUG)
    end_time = time.time() + timeout
    while time.time() < end_time:
        try:
            addon = xbmcaddon.Addon(addon_id)
            log_message(f"Looks like {addon_id} is running", level=xbmc.LOGDEBUG)
            return True
        except RuntimeError:
            pass  # Ignore the error and continue to wait
        
        log_message(f"Waiting for addon {addon_id} to be enabled...", level=xbmc.LOGDEBUG)
        time.sleep(5)  # wait for 5 seconds before checking again
    log_message(f"Waited for over {timeout} seconds for addon {addon_id}. Bailing out.", level=xbmc.LOGERROR)
    return False


def cleanup():
    global active_proxies, httpd
    
    # Log start of cleanup process
    log_message("Beginning cleanup process.", level=xbmc.LOGNOTICE)

    # Stop the main HTTP server
    try:
        httpd.shutdown()
        httpd.server_close()
        log_message("Main HTTP server terminated.", level=xbmc.LOGNOTICE)
    except Exception as e:
        log_message(f"Error while shutting down main HTTP server: {e}", level=xbmc.LOGERROR)


    # Stop all proxy servers
    for port, details in active_proxies.items():
        try:
            thread = details.get("thread")
            if thread:
                thread.join(1)  # Wait for thread to finish, with a 1-second timeout
            log_message(f"Proxy server on port {port} terminated.", level=xbmc.LOGNOTICE)
        except Exception as e:
            log_message(f"Error while shutting down proxy server on port {port}: {e}", level=xbmc.LOGERROR)

    log_message("Cleanup completed.", level=xbmc.LOGNOTICE)

def run_proxy(port, m3u8_url, epg_url, link, kodi_ip, name):
    log_message(f"Starting proxy on port {port} for Kodi IP: {kodi_ip}")
    server = ThreadedTCPServer(("", port), ProxyHTTPRequestHandler, m3u8_url, epg_url, link, kodi_ip, name)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.start()
    active_proxies[port] = {
        "name": name,
        "m3u8_url": m3u8_url,
        "epg_url": epg_url,
        "link": link,
        "kodi_ip": kodi_ip,
        "status": "IDLE",  # or any initial status you prefer
        "thread": server_thread
    }
    server.start_monitoring()
    return server

def log_message(message, level=xbmc.LOGDEBUG):
    if ENABLE_LOGGING or level == xbmc.LOGERROR:
        xbmc.log(f"IPTV_Encoder_Proxy: {message}", level=xbmc.LOGERROR)

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
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.bind(("localhost", port))
        s.close()
        return True
    except (socket.error, OSError):
        s.close()
        return False

def run():
    global httpd  # Ensure the httpd is global for cleanup to access
    log_message("Preparing to set up servers.")
    
    # Initialize the GracefulKodiMonitor
    log_message("Start up monitor for any shutdown requests.")
    monitor = GracefulKodiMonitor()

    # Spin up the master encoder
    port_to_use = find_available_port(start_port, end_port)
    if not port_to_use:
        log_message("No available ports found for master encoder!", level=xbmc.LOGERROR)
        return
    try:
        log_message(f"Starting Master encoder proxy on port {port_to_use}.")
        run_proxy(port_to_use, ADDON.getSetting('master_encoder_url'), '', '', '0.0.0.0', 'Master Kodi Encoder server')
        log_message(f"Now serving on port {port_to_use}")
    except Exception as e:
        log_message(f"Master proxy port execution error: {e}\n{traceback.format_exc()}", level=xbmc.LOGERROR)
  
    # Spin up all other slaves per settings
    for i in range(1, 4):
        ip_setting, encoder_url_setting = ADDON.getSetting(f"slave_{i}_ip"), ADDON.getSetting(f"slave_{i}_encoder_url")
        if ip_setting and ip_setting != "0.0.0.0" and encoder_url_setting:
            port_to_use = find_available_port(start_port, end_port)  # Another example range
            if not port_to_use:
                log_message(f"No available ports found for Slave {i} encoder!", level=xbmc.LOGERROR)
                continue
            try:
                log_message(f"Starting Slave {i} encoder proxy on port {port_to_use}.")
                run_proxy(port_to_use, encoder_url_setting, '', '', ip_setting, f'Slave Kodi Encoder server {i}')
                log_message(f"Now serving on port {port_to_use}")
            except Exception as e:
                log_message(f"Slave {i} proxy execution error: {e}\n{traceback.format_exc()}", level=xbmc.LOGERROR)

    # Finally, start the main server
    try:
        log_message(f"Starting main server on port {SERVER_PORT}.")
        httpd = socketserver.TCPServer(("", SERVER_PORT), MainHTTPRequestHandler)
        log_message(f"Now serving on port {SERVER_PORT}")
        while not monitor.abortRequested():
            if monitor.waitForAbort(1):  # Check every 1 second
                break
            httpd.handle_request()  # handle one request at a time

        log_message("Abort detected by Kodi. Stopping main loop...", level=xbmc.LOGNOTICE)
        cleanup()  # explicitly call the cleanup function here

    except Exception as e:
        log_message(f"port: {SERVER_PORT} Main execution error: {e}\n{traceback.format_exc()}", level=xbmc.LOGERROR)


if __name__ == '__main__':
    if wait_for_addon('plugin.program.iptv.merge'):
        log_message("plugin.program.iptv.merge is enabled, starting my addon...", level=xbmc.LOGDEBUG)
        log_message("Starting application...")
        run()
        log_message("Application terminated.")
    else:
        log_message("plugin.program.iptv.merge did not start in time. Exiting.", level=xbmc.LOGERROR)
