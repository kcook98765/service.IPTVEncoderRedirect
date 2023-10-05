import json
from urllib.request import urlopen, Request
from urllib.error import HTTPError
import xbmc
import xbmcaddon
import xbmcvfs
import os
import time

ADDON = xbmcaddon.Addon()
ADDON_PATH = ADDON.getAddonInfo("path")
ADDON_NAME = ADDON.getAddonInfo("name")
ADDON_ID = ADDON.getAddonInfo("id")

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

def send_jsonrpc(kodi_url, payload, headers=None):
    """
    Send a JSON-RPC request to a Kodi instance, whether it's local or remote.
    
    Parameters:
    - kodi_url (str): The URL of the Kodi instance.
    - payload (dict): The JSON-RPC payload.
    - headers (dict, optional): Any additional headers for the request.
    """
    
    # If it's a local request
    if kodi_url == 'local':
        command = json.dumps(payload)
        response = xbmc.executeJSONRPC(command)
        return json.loads(response)
    
    # If it's a remote request
    req = Request(kodi_url, json.dumps(payload).encode('utf-8'), headers or {})
    try:
        response = urlopen(req)
        response_content = response.read().decode('utf-8')
        return json.loads(response_content)
    except HTTPError as e:
        xbmc.log(f"Error sending JSON-RPC to remote Kodi: {e}", level=xbmc.LOGERROR)
        return None


def stop_kodi_playback(kodi_ip):
    payload = {
        "jsonrpc": "2.0",
        "method": "Player.Stop",
        "params": {
            "playerid": 1
        },
        "id": 1
    }
    send_jsonrpc(payload, f"http://{kodi_ip}:8080/jsonrpc")

def get_encoder_url_for_link(link):
    rows = query_database(
        'SELECT IP FROM active_streams WHERE link = ? AND status = "Active"',
        (link,)
    )
    if rows:
        for kodi_box in KODI_BOXES:
            if kodi_box['IP'] == rows[0][0]:
                return kodi_box['Encoder_URL']
    return None

def get_available_kodi_box():
    rows = query_database(
        'SELECT IP FROM active_streams WHERE status = "Inactive"'
    )
    if rows:
        for kodi_box in KODI_BOXES:
            if kodi_box['IP'] == rows[0][0]:
                return kodi_box
    return None


