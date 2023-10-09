import xbmc, xbmcaddon, xbmcvfs, xbmcgui, xbmcplugin
import http.server
import socketserver
from urllib.request import urlopen, quote, urlparse
from urllib.error import URLError
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

class ProxyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):

    def do_GET(self):
        log_message("ProxyHTTPRequestHandler - Starting GET request handling.")
        # Update last activity time for the proxy instance
        self.server.last_activity = time.time()

        url = None

        if self.path.endswith('.m3u8'):
            log_message("Path ends with .m3u8")
            if self.server.m3u8_url == 'http://localhost:52104/playlist.m3u8' :
                log_message(f"Master m3u8, processing")
                self.handle_playlist_request()
            else:
                url = self.server.m3u8_url + self.path
                log_message(f"Not master m3u8, updating URL to: {url}")
        
        elif self.path.endswith('epg.xml'):
            if self.server.epg_url == 'http://localhost:52104/epg.xml':
                log_message(f"Master EPG, processing")
                self.handle_epg_request()
            else:
                url = self.server.epg_url + self.path
                log_message(f"Not master EPG, updating URL to: {url}")

        # If the path matches any of our conditions
        if url:
            try:
                with urllib.request.urlopen(url) as response:
                    self.send_response(response.status)
                    for key, value in response.getheaders():
                        self.send_header(key, value)
                    self.end_headers()
                    self.wfile.write(response.read())
                    log_message(f"Successfully fetched data from URL: {url}")
            except:
                self.server.status = "ERROR"
                log_message(f"Failed to fetch data from URL: {url}", level=xbmc.LOGERROR)
        else:
            self.send_response(404)
            self.end_headers()
            log_message(f"URL did not match any conditions, returning 404 for path: {self.path}")

    def handle_epg_request(self):
        log_message("Received request for EPG.")
        try:
            content = self.fetch_content(self.server.epg_url)
            content_bytes = content.encode('utf-8')  # Encode the content as bytes
    
            self.send_response(200)
            self.send_header('Content-type', 'application/xml')
            self.end_headers()
            self.wfile.write(content_bytes)  # Write the encoded content as bytes
        except URLError as e:
            self.handle_error(f"Unexpected error: {e}")

    def handle_playlist_request(self):
        log_message("Received request for playlist.")
        try:
            content = self.fetch_content(self.server.m3u8_url)
            transformed_content = self.transform_playlist_content(content)
            self.send_response(200)
            self.send_header('Content-type', 'application/vnd.apple.mpegurl')
            self.end_headers()
            self.wfile.write(transformed_content.encode())
        except Exception as e:
            self.handle_error(e)

    def transform_playlist_content(self, content):
        lines = content.split('\n')
        new_lines = []
        for line in lines:
            if line.startswith('plugin://'):
                encoded_line = quote(line, safe='')
                new_url = f"http://{xbmc.getIPAddress()}:{self.server.server_address[1]}/play?link={encoded_line}"
                new_lines.append(new_url)
            else:
                new_lines.append(line)
        return '\n'.join(new_lines)

    def fetch_content(self, url):
        response = urlopen(url)
        return response.read().decode('utf-8')

    def handle_error(self, e):
        log_message(f"HTTP request handling error: {e}\n{traceback.format_exc()}", level=xbmc.LOGERROR)
        self.send_response(500)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(str(e).encode())

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    last_activity = time.time()
    daemon_threads = True

    def __init__(self, server_address, handler, m3u8_url, epg_url, link, kodi_ip):
        log_message("Initializing ThreadedTCPServer.")
        super().__init__(server_address, handler)
        self.m3u8_url = m3u8_url
        self.epg_url = epg_url
        self.link = link
        self.kodi_ip = kodi_ip
        self.status = "IDLE"
        if self.m3u8_url == "" and self.epg_url == "":
            log_message("Not an EPG or M3U8 proxy, allow auto monitor")
            self.start_monitoring()  # Start monitoring when the server is created
        else:
            log_message("Is an EPG or M3U8 proxy, do not auto monitor")

    def start_monitoring(self):
        def monitor():
            while True:
                time_since_last_activity = time.time() - self.last_activity
                if time_since_last_activity > 120 and self.status != "IDLE":
                    # Stop Kodi playback
                    log_message(f"Stopping Kodi playback for IP {self.kodi_ip} due to inactivity.")
                    kodi = KodiJsonRPC(self.kodi_ip)
                    kodi.stop_play()
                    self.status = "IDLE"
                    log_message(f"Proxy for Kodi IP {self.kodi_ip} set to IDLE after 120 Sec inactivity.", level=xbmc.LOGDEBUG)
                time.sleep(10)  # Check every 10 seconds
                log_message(f"Monitoring thread checked for Kodi IP {self.kodi_ip}, status: {self.status}")
        
        log_message("Starting monitoring thread.")
        monitoring_thread = threading.Thread(target=monitor)
        monitoring_thread.daemon = True  # So the monitoring thread exits when the main program does
        monitoring_thread.start()

class KodiJsonRPC:
    def __init__(self, kodi_ip='localhost', kodi_port=8080, username='kodi', password='kodi'):
        log_message(f"Initializing KodiJsonRPC for IP: {kodi_ip}, port: {kodi_port}")
        self.base_url = f"http://{kodi_ip}:{kodi_port}/jsonrpc"
        self.kodi_ip = kodi_ip
        self.auth = b64encode(f"{username}:{password}".encode()).decode('utf-8')

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

        req = urllib.request.Request(self.base_url, data=json.dumps(payload).encode(), headers=headers)
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read())
            log_message(f"Received response from Kodi ({self.base_url}): {result}")
            return result

    def play_path(self, path):
        log_message(f"Attempting to play path: {path}")
        params = {
            "item": {
                "file": path
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
    # This handler will process the incoming requests on port 9191
    
    def do_GET(self):
        log_message(f"MainHTTPRequestHandler - Handling GET request for path: {self.path}")
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == "/play":
            link = parsed_path.query.split("link=")[-1]
            
            log_message(f"MainHTTPRequestHandler - Handling GET request for link: {link}")
        
            # Search for a proxy playing this link
            proxy_port = None
            for port, details in active_proxies.items():
                if details['link'] == link and details['status'] == "RUNNING":
                    log_message(f"MainHTTPRequestHandler - found active proxy for: {link} on port {port}")
                    proxy_port = port
                    break
        
            # If not found, choose an available proxy and update its link and status
            if proxy_port is None:
                for port, details in active_proxies.items():
                    if details['status'] != "RUNNING":
                        log_message(f"MainHTTPRequestHandler - found inactive proxy for: {link} on port {port}")
                        proxy_port = port
                        details['link'] = link
                        details['status'] = "RUNNING"
                        # Send the "play" command to the associated Kodi
                        log_message(f"MainHTTPRequestHandler - sending kodi {details['kodi_ip']} a play command for {link} on port {port}")
                        kodi_rpc = KodiJsonRPC(kodi_ip=details['kodi_ip'])
                        kodi_rpc.play_path(link)
                        break
        
            if proxy_port:
                encoder_url = active_proxies[proxy_port]['m3u8_url']  # or whatever attribute is needed
                # Redirect to encoder_url and initiate Kodi playback
        
                kodi_rpc = KodiJsonRPC(kodi_ip=active_proxies[proxy_port]['kodi_ip'])
                kodi_rpc.play_path(encoder_url)  # assuming this is how you initiate playback
        
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
            self.wfile.write(json.dumps(active_proxies).encode('utf-8'))
            log_message("Received /status endpoint request.")
        
        else:
            self.send_response(404)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Not Found")
            log_message("Received unknown endpoint request, returning 404.")

class GracefulKodiMonitor(xbmc.Monitor):
    def __init__(self, cleanup_callback):
        super(GracefulKodiMonitor, self).__init__()
        self.cleanup_callback = cleanup_callback

    def onAbortRequested(self):
        self.cleanup_callback()

def cleanup():
    global active_proxies, httpd

    # Stop the main HTTP server
    httpd.shutdown()
    httpd.server_close()
    log_message("Main HTTP server terminated.")

    # Stop all proxy servers
    for port, details in active_proxies.items():
        thread = details.get("thread")
        if thread:
            thread.join(2)  # Wait for thread to finish, with a 2-second timeout

    log_message("All proxy servers terminated.")
    log_message("Cleanup completed.")

def run_proxy(port, m3u8_url, epg_url, link, kodi_ip):
    log_message(f"Starting proxy on port {port} for Kodi IP: {kodi_ip}")
    server = ThreadedTCPServer(("", port), ProxyHTTPRequestHandler, m3u8_url, epg_url, link, kodi_ip)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.start()
    active_proxies[port] = {
        "m3u8_url": m3u8_url,
        "epg_url": epg_url,
        "link": link,
        "kodi_ip": kodi_ip,
        "status": "RUNNING",  # or any initial status you prefer
        "thread": server_thread
    }
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
    monitor = GracefulKodiMonitor(cleanup)
    
    try:
        log_message("Starting main server on port 9191.")
        httpd = socketserver.TCPServer(("", 9191), MainHTTPRequestHandler)
        log_message("Now serving on port 9191")
        while not monitor.abortRequested():
            httpd.handle_request()  # handle one request at a time
            if monitor.waitForAbort(1):  # wait 1 second between requests
                break

    except Exception as e:
        log_message(f"9191 Main execution error: {e}\n{traceback.format_exc()}", level=xbmc.LOGERROR)

    try:
        log_message("Starting main proxy m3u8 server on port 9192.")
        run_proxy(9192, 'http://localhost:52104/playlist.m3u8', '', '', '0.0.0.0')
        log_message("Now serving on port 9192")

    except Exception as e:
        log_message(f"9192 Main execution error: {e}\n{traceback.format_exc()}", level=xbmc.LOGERROR)

    try:
        log_message("Starting main proxy epg.xml server on port 9193.")
        run_proxy(9193, '', 'http://localhost:52104/epg.xml', '', '0.0.0.0')
        log_message("Now serving on port 9193")

    except Exception as e:
        log_message(f"9193 Main execution error: {e}\n{traceback.format_exc()}", level=xbmc.LOGERROR)

    # spin up each encoder/kodi proxy, start with the master
    port_to_use = find_available_port(start_port, end_port)
    if not port_to_use:
        log_message("No available ports found for master encoder!", level=xbmc.LOGERROR)
        return
    try:
        log_message(f"Starting Master encoder proxy on port {port_to_use}.")
        run_proxy(port_to_use, ADDON.getSetting('master_encoder_url'), '', '', '0.0.0.0')
        log_message(f"Now serving on port {port_to_use}")
    except Exception as e:
        log_message(f"Master proxy port execution error: {e}\n{traceback.format_exc()}", level=xbmc.LOGERROR)
  
    # spin up all other slaves per settings
    for i in range(1, 4):
        ip_setting, encoder_url_setting = ADDON.getSetting(f"slave_{i}_ip"), ADDON.getSetting(f"slave_{i}_encoder_url")
        if ip_setting and ip_setting != "0.0.0.0" and encoder_url_setting:
            port_to_use = find_available_port(start_port, end_port)  # Another example range
            if not port_to_use:
                log_message(f"No available ports found for Slave {i} encoder!", level=xbmc.LOGERROR)
                continue
            try:
                log_message(f"Starting Slave {i} encoder proxy on port {port_to_use}.")
                run_proxy(port_to_use, encoder_url_setting, '', '', ip_setting)
                log_message(f"Now serving on port {port_to_use}")
            except Exception as e:
                log_message(f"Slave {i} proxy execution error: {e}\n{traceback.format_exc()}", level=xbmc.LOGERROR)

if __name__ == '__main__':
    log_message("Starting application...")
    run()
    log_message("Application terminated.")