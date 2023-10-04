import xbmc
import xbmcaddon
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, quote
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import json  # import the json module
import telnetlib
import time
import threading
import sqlite3

from database_helper import (
    create_database, populate_kodi_boxes, query_database, 
    modify_database, store_address, store_link,
    insert_into_active_streams, update_active_stream_status,
    truncate_addresses_table
)

from kodi_rpc import (
    send_jsonrpc, stop_kodi_playback, get_encoder_url_for_link, 
    get_available_kodi_box, KODI_BOXES
)

# Get the add-on's settings
addon = xbmcaddon.Addon()

# Read Master settings
master_ip = addon.getSetting('master_ip')
master_encoder_url = addon.getSetting('master_encoder_url')
server_port = addon.getSetting('server_port')

# Read Slave settings
slave_1_ip = addon.getSetting('slave_1_ip')
slave_1_encoder_url = addon.getSetting('slave_1_encoder_url')

slave_2_ip = addon.getSetting('slave_2_ip')
slave_2_encoder_url = addon.getSetting('slave_2_encoder_url')

slave_3_ip = addon.getSetting('slave_3_ip')
slave_3_encoder_url = addon.getSetting('slave_3_encoder_url')

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


class TelnetPoller:
    def __init__(self, host, username, password, command, poll_interval):
        self.host = host
        self.username = username
        self.password = password
        self.command = command
        self.poll_interval = poll_interval
        self.tn = None

    def connect(self):
        try:
            self.tn = telnetlib.Telnet(self.host)
            self.tn.read_until(b"login: ")
            self.tn.write(self.username.encode('ascii') + b"\n")
            self.tn.read_until(b"Password: ")
            self.tn.write(self.password.encode('ascii') + b"\n")
        except Exception as e:
            xbmc.log(f"Telnet connection error: {e}", level=xbmc.LOGERROR)


    def poll_netstat(self):
        try:
            truncate_addresses_table()  # Truncate the table before updating
            self.tn.write(self.command.encode('ascii') + b"\n")
            output = self.tn.read_until(b"$").decode('ascii')
            for line in output.split('\n')[2:]:
                parts = line.split()
                if len(parts) < 6:
                    continue
                local_address, foreign_address, state = parts[3], parts[4], parts[5]
                if 'telnet' in local_address:
                    continue
                if state in {'ESTABLISHED', 'SYN_SENT', 'SYN_RECV'}:
                    store_address(foreign_address, time.strftime("%Y-%m-%d %H:%M:%S"))
        except Exception as e:
            xbmc.log(f"Telnet polling error: {e}", level=xbmc.LOGERROR)
            self.connect()  # Attempt to reconnect

    def start_polling(self):
        self.connect()
        previous_addresses = set()  # Set to track previous clients

        while True:
            self.poll_netstat()
            
            # Fetch all the current addresses from the database
            rows = query_database('SELECT foreign_address FROM addresses')
            current_addresses = set(row[0] for row in rows)

            new_clients = current_addresses - previous_addresses
            disconnected_clients = previous_addresses - current_addresses

            # Handle new and disconnected clients here
#            for client in new_clients:
                # Record this new client
                # ... [Your logic to handle new client]

            for client in disconnected_clients:
                # Check if there are no clients connected to the Kodi instance and send "Stop" command
                associated_kodi_ip = get_kodi_for_client(client)  # This method should return the Kodi IP associated with a client
                if not any([client for client in current_addresses if associated_kodi_ip == get_kodi_for_client(client)]):
                    stop_kodi_playback(associated_kodi_ip)

            previous_addresses = current_addresses

            time.sleep(self.poll_interval)


class MyHandler(BaseHTTPRequestHandler):

    def handle_error(self, e, error_message=None):
        xbmc.log(f"HTTP request handling error: {e}", level=xbmc.LOGERROR)
        self.send_response(500)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        if error_message:
            self.wfile.write(error_message.encode())

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
            with play_request_lock:
                query_params = parse_qs(parsed_path.query)
                link = query_params.get('link', [''])[0]

                # Store the link as soon as it's gathered
                store_link(link)

                # Check if the link exists in the active_streams table
                encoder_url = get_encoder_url_for_link(link)
                if encoder_url:
                    # Redirect to the encoder URL
                    self.send_response(302)
                    self.send_header('Location', encoder_url)
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
                    timestamp = time.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                    current_time = time.time()
                    duration = current_time - time.mktime(timestamp)
    
                    if duration > (4 * 60 * 60):  # 4 hours in seconds
                        associated_kodi_ip = get_kodi_for_link(link)  # This method should return the Kodi IP associated with a link
                        stop_kodi_playback(associated_kodi_ip)

def run():
    try:
        create_database()  # Create database at the start of the application
        populate_kodi_boxes()  # Populate kodi_boxes table at the start of the application
    
        poller = TelnetPoller(
            host="your_host",
            username="your_username",
            password="your_password",
            command="netstat -t",
            poll_interval=300  # 5 minutes in seconds
        )
        polling_thread = threading.Thread(target=poller.start_polling)
        polling_thread.daemon = True
        polling_thread.start()
    
        server_address = ('', server_port)
        httpd = HTTPServer(server_address, MyHandler)
        httpd.serve_forever()
    except Exception as e:
        xbmc.log(f"Main execution error: {e}", level=xbmc.LOGERROR)



if __name__ == '__main__':
    run()