import ctypes
import sqlite3
import subprocess
import sys
import time

import requests
import os

# Define the database file path
db_path = '../db/devices.db'

# Ensure the directory exists if needed
os.makedirs(os.path.dirname(db_path), exist_ok=True)

# Create the database
conn = sqlite3.connect(db_path)
conn.close()

# Check if the database file exists
if os.path.exists(db_path):
    print(f"Database '{db_path}' created successfully!")
else:
    print(f"Failed to create the database '{db_path}'.")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def clear_arp_cache():
    if os.name == 'nt':  # Windows
        if not is_admin():
            print("This script needs to be run as an administrator to clear the ARP cache.")
            return
        try:
            print("Clearing ARP cache on Windows...")
            subprocess.run(['netsh', 'interface', 'ip', 'delete', 'arpcache'], capture_output=True, text=True, shell=True, check=True)
            print("ARP cache cleared successfully.")
        except subprocess.CalledProcessError as e:
            print(f"An error occurred while clearing ARP cache: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
    else:  # Linux/macOS
        try:
            print("Clearing ARP cache on Linux/macOS...")
            subprocess.run(['ip', '-s', 'neigh', 'flush', 'all'], capture_output=True, text=True, shell=True, check=True)
            print("ARP cache cleared successfully.")
        except subprocess.CalledProcessError as e:
            print(f"An error occurred while clearing ARP cache: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

def save_device_info(mac, device_name, ip, vendor):
    print(f"saving device name", mac, device_name)
    conn = None
    try:
        conn = sqlite3.connect('../db/devices.db')
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS devices (
                                MAC_ADDRESS TEXT PRIMARY KEY,
                                IP TEXT,
                                Device_Name TEXT,
                                MAC_VENDOR TEXT,
                                Availability TEXT
                              )''')

        cursor.execute("INSERT OR REPLACE INTO devices (MAC_ADDRESS, IP, Device_Name, MAC_VENDOR, Availability) VALUES (?, ?, ?, ?, ?)", (mac, ip, device_name, vendor, 'False'))
        conn.commit()
        print("Table Created")
        cursor.execute('SELECT * FROM devices WHERE MAC_ADDRESS = ?', (mac,))
        updated_record = cursor.fetchone()
        print("Updated Record in DB:", updated_record)

    except sqlite3.Error as e:
        print("SqLite error:", e)
    finally:
        if conn:
            conn.close()

def update_device_info(mac, device_name):
    print(f"saving device name", mac, device_name)
    conn = None
    try:
        conn = sqlite3.connect('../db/devices.db')
        cursor = conn.cursor()

        cursor.execute("UPDATE devices SET Device_Name = ? WHERE MAC_ADDRESS = ?", (device_name, mac))
        conn.commit()
        print("Table Created")
        cursor.execute('SELECT * FROM devices WHERE MAC_ADDRESS = ?', (mac,))
        updated_record = cursor.fetchone()
        print("Updated Record in DB:", updated_record)

    except sqlite3.Error as e:
        print("SqLite error:", e)
    finally:
        if conn:
            conn.close()


def fetch_device_name(device_name):
    print(f"fetching device names", device_name)
    conn = None
    try:
        conn = sqlite3.connect('../db/devices.db')
        cursor = conn.cursor()
        cursor.execute("SELECT device_name FROM devices WHERE MAC_ADDRESS=?", (device_name,))
        result = cursor.fetchone()
        print(f"result in fetch dev name", result)
        if result:
            return result[0]
        else:
            return None
    except sqlite3.Error as e:
        print("SQfLite error:", e)
        return None
    finally:
        if conn:
            conn.close()



def arp_scan(interface_ip, start_ip, end_ip):
    print(f"arp scanning")
    clear_arp_cache()
    time.sleep(2)  # Allow time for ARP table to repopulate
    devices = []
    # Iterate over the IP range
    for i in range(start_ip, end_ip + 1):
        ip = f"{interface_ip[:interface_ip.rfind('.') + 1]}{i}"
        result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
        output = result.stdout
        #result = result.communicate()[0].decode().split('\n')

        for line in output.splitlines():
            parts = line.split()
            if len(parts) == 3:
                ip, mac, _ = parts
                print(f"Found device: IP={ip}, MAC={mac}")
                mac_vendor = query_mac_address_lookup(mac)
                save_device_info(mac,fetch_device_name(mac) if fetch_device_name(mac) else 'Unknown', ip, mac_vendor)
                devices.append(
                    {'Device_Name': fetch_device_name(mac) if fetch_device_name(mac) else 'Unknown', 'IP': ip, 'MAC_Address': mac, 'MAC_Vendor': mac_vendor, 'Availability': 'False'})
    print(devices)
    return devices


def get_mac_address(ip_address, device_list):
    print(f"get_mac_address")
    for device in device_list:
        if device['IP'] == ip_address:
            return device['MAC Address']
    return None


def query_mac_address_lookup(mac_address):
    print(f"def query_mac_address_lookup")
    oui = mac_address[:8].replace(':', '')
    url = f"https://api.macvendors.com/{oui}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text.strip()
        else:
            return "Unknown"
    except Exception as e:
        print(f"Error querying MAC address lookup service: {e}")
        return "Unknown"
