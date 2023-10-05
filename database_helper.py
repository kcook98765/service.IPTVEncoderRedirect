import sqlite3
import xbmc
import xbmcaddon
import xbmcvfs
import os
import time

ADDON = xbmcaddon.Addon()

profilePath = xbmcvfs.translatePath( ADDON.getAddonInfo('profile') )
if not os.path.exists(profilePath):
    os.makedirs(profilePath)

DATABASE_NAME = xbmcvfs.translatePath(os.path.join(profilePath, 'IPTVEncoderRedirect_data.db'))

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



def create_database():
    conn = sqlite3.connect(DATABASE_NAME)
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS kodi_boxes (
            id INTEGER PRIMARY KEY,
            actor TEXT,
            IP TEXT,
            encoder_url TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS addresses (
            foreign_address TEXT PRIMARY KEY,
            first_seen TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS links (
            link TEXT PRIMARY KEY,
            timestamp TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS active_streams (
            id INTEGER PRIMARY KEY,
            box_id INTEGER,
            status TEXT CHECK(status IN ('Active', 'Inactive')),
            link TEXT,
            FOREIGN KEY (box_id) REFERENCES kodi_boxes(id)
        )
    ''')

    conn.commit()
    conn.close()

def populate_kodi_boxes():
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        c = conn.cursor()

        for box in KODI_BOXES:
            c.execute(
                'INSERT OR IGNORE INTO kodi_boxes (Actor, IP, Encoder_URL) VALUES (?, ?, ?)',
                (box["Actor"], box["IP"], box["Encoder_URL"])
            )
        
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        xbmc.log(f"Error populating kodi_boxes table: {e}", level=xbmc.LOGERROR)

   
def query_database(sql, parameters=()):
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        c = conn.cursor()
        c.execute(sql, parameters)
        rows = c.fetchall()
        conn.close()
        return rows
    except sqlite3.Error as e:
        xbmc.log(f"Database query error: {e}", level=xbmc.LOGERROR)
        return []

def modify_database(sql, parameters=()):
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        c = conn.cursor()
        c.execute(sql, parameters)
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        xbmc.log(f"Database modification error: {e}", level=xbmc.LOGERROR)

def store_address(foreign_address, first_seen):
    modify_database(
        'INSERT OR IGNORE INTO addresses (foreign_address, first_seen) VALUES (?, ?)',
        (foreign_address, first_seen)
    )

def store_link(link):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    modify_database(
        'INSERT OR IGNORE INTO links (link, timestamp) VALUES (?, ?)',
        (link, timestamp)
    )

def insert_into_active_streams(IP, status, link):
    modify_database(
        'INSERT INTO active_streams (IP, status, link) VALUES (?, ?, ?)',
        (IP, status, link)
    )

def update_active_stream_status(id, status):
    modify_database(
        'UPDATE active_streams SET status = ? WHERE id = ?',
        (status, id)
    )

def truncate_addresses_table():
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        c = conn.cursor()
        c.execute("DELETE FROM addresses")
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        xbmc.log(f"Error truncating addresses table: {e}", level=xbmc.LOGERROR)

