import socket
import threading
import os
import random
import time
import uuid
from datetime import datetime
from cryptography.fernet import Fernet
import re

# ====== CONFIG ======
PORT = 6666
UDP_PORT = 7777
BUFFER = 1024
MAX_MESSAGE_LENGTH = 500
RECONNECT_DELAY = 10  # seconds between reconnect attempts

peers = {}
lock = threading.Lock()
message_history = set()
encryption_keys = {}

# ====== UTILITIES ======
def clear():
    os.system('clear' if os.name == 'posix' else 'cls')

def random_name():
    return "anon" + str(random.randint(1000, 9999))

def generate_msg_id():
    return str(uuid.uuid4())

def timestamp():
    return datetime.now().strftime("[%H:%M:%S]")

def print_connected(ip):
    print(f"\n{timestamp()} connected: {ip}\n<@{name}> ", end="", flush=True)

def generate_key():
    return Fernet.generate_key()

def validate_ip(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return re.match(pattern, ip) is not None

def validate_message(msg):
    if len(msg) > MAX_MESSAGE_LENGTH:
        return False
    # Basic sanitization
    msg = msg.replace('\n', ' ').replace('\r', ' ').strip()
    return msg

# ====== ENCRYPTION ======
def encrypt_message(key, message):
    fernet = Fernet(key)
    return fernet.encrypt(message.encode())

def decrypt_message(key, encrypted_message):
    try:
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_message).decode()
    except:
        return None

# ====== PEER COMMUNICATION ======
def send_all(msg_id, msg):
    with lock:
        current_peers = list(peers.items())
    
    for ip, (conn, key) in current_peers:
        try:
            encrypted_msg = encrypt_message(key, f"{msg_id}|{msg}")
            conn.sendall(len(encrypted_msg).to_bytes(4, 'big'))
            conn.sendall(encrypted_msg)
        except:
            with lock:
                if ip in peers:
                    del peers[ip]
            continue

def send_whisper(target_ip, msg):
    with lock:
        peer_data = peers.get(target_ip)
    
    if peer_data:
        conn, key = peer_data
        try:
            msg_id = generate_msg_id()
            encrypted_msg = encrypt_message(key, f"{msg_id}|{msg}")
            conn.sendall(len(encrypted_msg).to_bytes(4, 'big'))
            conn.sendall(encrypted_msg)
            return True
        except:
            with lock:
                if target_ip in peers:
                    del peers[target_ip]
            return False
    return False

def recv_from_peer(conn, addr, key):
    ip = addr[0]
    buffer = b''
    
    while True:
        try:
            # Read message length
            raw_length = conn.recv(4)
            if not raw_length:
                break
            msg_length = int.from_bytes(raw_length, 'big')
            
            # Read message data
            while len(buffer) < msg_length:
                data = conn.recv(min(msg_length - len(buffer), BUFFER))
                if not data:
                    break
                buffer += data
            
            if len(buffer) != msg_length:
                break
                
            # Decrypt and process message
            decrypted = decrypt_message(key, buffer)
            if not decrypted:
                break
                
            raw = decrypted.strip()
            if "|" not in raw:
                continue
                
            msg_id, msg = raw.split("|", 1)
            if msg_id in message_history:
                continue
                
            message_history.add(msg_id)
            print(f"\n{timestamp()} {msg}\n<@{name}> ", end="", flush=True)
            send_all(msg_id, msg)
            
            buffer = b''
            
        except (ConnectionResetError, socket.error):
            break
    
    with lock:
        if ip in peers:
            del peers[ip]
    conn.close()
    print(f"\n{timestamp()} disconnected: {ip}\n<@{name}> ", end="", flush=True)

# ====== SERVER SETUP ======
def server_thread():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', PORT))
    s.listen()

    while True:
        try:
            conn, addr = s.accept()
            ip = addr[0]
            
            # Key exchange
            key = generate_key()
            conn.sendall(key)
            peer_key = conn.recv(BUFFER)
            
            with lock:
                if ip not in peers:
                    peers[ip] = (conn, peer_key)
                    
            threading.Thread(target=recv_from_peer, args=(conn, addr, peer_key), daemon=True).start()
            print_connected(ip)
            
        except Exception as e:
            continue

# ====== CONNECTION MANAGEMENT ======
def connect_to_peer(ip):
    if ip == my_ip or (ip in peers and peers[ip][0].getpeername()[0] == ip):
        return
    
    while True:
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.settimeout(5)
            conn.connect((ip, PORT))
            
            # Key exchange
            key = generate_key()
            conn.sendall(key)
            peer_key = conn.recv(BUFFER)
            
            with lock:
                peers[ip] = (conn, peer_key)
                
            threading.Thread(target=recv_from_peer, args=(conn, (ip, PORT), peer_key), daemon=True).start()
            print_connected(ip)
            return
            
        except (socket.timeout, ConnectionRefusedError, socket.error) as e:
            time.sleep(RECONNECT_DELAY)
            continue
        except Exception as e:
            print(f"\n{timestamp()} fail connect to {ip}: {str(e)}\n<@{name}> ", end="", flush=True)
            return

# ====== BROADCAST DISCOVERY ======
def udp_broadcast():
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    
    while True:
        try:
            udp.sendto(my_ip.encode(), ('', UDP_PORT))
        except:
            pass
        time.sleep(5)

def udp_listener():
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind(('', UDP_PORT))
    
    while True:
        try:
            data, addr = udp.recvfrom(BUFFER)
            peer_ip = data.decode().strip()
            if peer_ip != my_ip and validate_ip(peer_ip):
                threading.Thread(target=connect_to_peer, args=(peer_ip,), daemon=True).start()
        except:
            continue

# ====== NETWORK HELPERS ======
def get_my_ip():
    try:
        s = socket.socket(socket.A
