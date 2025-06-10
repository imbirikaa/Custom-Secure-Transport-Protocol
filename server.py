import os
import threading
import time
import customtkinter as ctk
import base64
import hashlib
import struct
from collections import defaultdict, deque
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad
from scapy.all import IP, UDP, Raw, send, sniff, Packet, bind_layers
from scapy.fields import ShortField, IntField

# --- CONFIGURATION FOR WINDOWS SERVER ---
LOOPBACK_INTERFACE = "VirtualBox Host-Only Ethernet Adapter"
SERVER_IP = '192.168.56.1' # IP of this Windows Server machine
SERVER_DATA_PORT = 5001      # Port this server will listen on for data
SAVE_FOLDER = 'received_files'

# region --- SCAPY & APP CONFIG ---
class FileTransferHeader(Packet):
    name = "FileTransferHeader"
    fields_desc = [ShortField("file_id", 0), IntField("chunk_offset", 0), ShortField("flags", 0)]
bind_layers(UDP, FileTransferHeader, dport=SERVER_DATA_PORT)

class ACKHeader(Packet):
    name = "ACKHeader"
    fields_desc = [ShortField("file_id", 0), IntField("acked_offset", 0), ShortField("status", 0)]

FLAG_MORE_FRAGMENTS = 0x01
# endregion

class ServerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.received_fragments = defaultdict(dict)
        self.file_metadata = defaultdict(dict)
        self.server_thread = None
        self.base64_key = ""
        self.completed_transfers = deque(maxlen=100)
        self.title("Secure Transfer Server")
        self.geometry("750x550")
        self.configure(fg_color='#2D2D2D')
        self.resizable(False, False)
        ctk.set_appearance_mode("dark")
        self.create_widgets()

    def create_widgets(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        header_label = ctk.CTkLabel(self, text="Secure File Transfer Server", font=ctk.CTkFont(size=24, weight="bold"), text_color="#00A9E0")
        header_label.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        controls_frame = ctk.CTkFrame(self, fg_color="transparent")
        controls_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        self.key_entry = ctk.CTkEntry(controls_frame, placeholder_text="AES Key will be generated here", height=40, border_width=1)
        self.key_entry.grid(row=0, column=0, columnspan=3, pady=10, sticky="ew")
        controls_frame.grid_columnconfigure(0, weight=1)
        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.grid(row=3, column=0, padx=20, pady=10, sticky="ew")
        self.start_button = ctk.CTkButton(button_frame, text="Start Server", height=40, command=self.run_server)
        self.start_button.pack(side="left", padx=(0, 10))
        self.copy_button = ctk.CTkButton(button_frame, text="Copy Key", height=40, command=self.copy_key)
        self.copy_button.pack(side="left", padx=(0, 10))
        self.regen_button = ctk.CTkButton(button_frame, text="Regenerate Key", height=40, command=self.regenerate_key)
        self.regen_button.pack(side="left", padx=(0, 10))
        log_frame = ctk.CTkFrame(self, fg_color="transparent")
        log_frame.grid(row=2, column=0, padx=20, pady=10, sticky="nsew")
        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)
        self.log_area = ctk.CTkTextbox(log_frame, font=("Consolas", 12), border_width=1, fg_color="#242424")
        self.log_area.grid(row=0, column=0, sticky="nsew")
        self.log_area.tag_config('SUCCESS', foreground='#4CAF50'); self.log_area.tag_config('ERROR', foreground='#F44336')
        self.log_area.tag_config('INFO', foreground='#2196F3'); self.log_area.tag_config('WARN', foreground='#FFC107')
        self.log_area.tag_config('RECEIVE', foreground='#9C27B0')
        self.status_label = ctk.CTkLabel(self, text="Stopped", text_color="#A0A0A0", height=25, anchor="w")
        self.status_label.grid(row=4, column=0, padx=20, pady=(5, 10), sticky="ew")
        self.regenerate_key()

    def log(self, message, level='INFO'):
        timestamp = time.strftime('%H:%M:%S')
        self.log_area.insert("end", f"[{timestamp}] ", "normal")
        self.log_area.insert("end", f"[{level}] ", (level.upper(),))
        self.log_area.insert("end", f"{message}\n", "normal")
        self.log_area.see("end")
        self.update_idletasks()

    def regenerate_key(self):
        key = get_random_bytes(32)
        self.base64_key = base64.b64encode(key).decode()
        self.key_entry.delete(0, "end"); self.key_entry.insert(0, self.base64_key)
        self.log("New AES key generated.", "INFO")

    def copy_key(self):
        self.clipboard_clear(); self.clipboard_append(self.base64_key)
        self.log("AES key copied to clipboard.", "SUCCESS")

    def run_server(self):
        self.start_button.configure(state="disabled")
        self.status_label.configure(text=f"Listening on interface '{LOOPBACK_INTERFACE}'...")
        self.log(f"Server starting on interface '{LOOPBACK_INTERFACE}'...", "INFO")
        self.server_thread = threading.Thread(target=self._start_server_logic, daemon=True)
        self.server_thread.start()

    def _start_server_logic(self):
        try:
            # New sniff filter for UDP data on our designated port
            sniff(iface=LOOPBACK_INTERFACE, filter=f"udp and dst port {SERVER_DATA_PORT}",
                prn=self.packet_handler, store=0)
        except Exception as e:
            self.log(f"Server sniffing error: {e}. Is the interface name correct?", "ERROR")
        finally:
            self.log("Server sniffing stopped.", "WARN")
            self.status_label.configure(text="Stopped")
            self.start_button.configure(state="normal")

    def send_ack(self, client_ip, client_ack_port, file_id, acked_offset):
        # ACK packet now also uses UDP
        ack_packet = (IP(dst=client_ip, src=SERVER_IP) /
                    UDP(sport=SERVER_DATA_PORT, dport=client_ack_port) /
                    ACKHeader(file_id=file_id, acked_offset=acked_offset))
        send(ack_packet, iface=LOOPBACK_INTERFACE, verbose=0)

    def packet_handler(self, packet):
        if FileTransferHeader not in packet: return
        
        file_id = packet[FileTransferHeader].file_id
        if file_id in self.completed_transfers:
            self.log(f"Received duplicate packet for completed transfer ID {file_id}. Discarding.", "WARN")
            return
            
        header, raw = packet[FileTransferHeader], packet[Raw]
        chunk_offset = header.chunk_offset
        client_ip = packet[IP].src
        client_ack_port = packet[UDP].sport # Get the client's source port to send the ACK back

        if chunk_offset == 0 and not self.file_metadata.get(file_id):
            try:
                offset = 0
                key_len=int.from_bytes(raw.load[offset:offset+4],'big'); offset+=4
                key_b64=raw.load[offset:offset+key_len].decode(); offset+=key_len
                iv_len=int.from_bytes(raw.load[offset:offset+4],'big'); offset+=4
                iv=raw.load[offset:offset+iv_len]; offset+=iv_len
                name_len=int.from_bytes(raw.load[offset:offset+4],'big'); offset+=4
                filename=raw.load[offset:offset+name_len].decode(); offset+=name_len
                size=int.from_bytes(raw.load[offset:offset+8],'big'); offset+=8
                original_hash = raw.load[offset:offset+32]; offset += 32
                total_chunks = int.from_bytes(raw.load[offset:offset+4], 'big'); offset += 4
                if key_b64 != self.base64_key:
                    self.log(f"Key mismatch for transfer {file_id}. Discarding.", "ERROR"); return
                self.file_metadata[file_id] = {'iv': iv, 'filename': filename, 'size': size, 'hash': original_hash, 'total_chunks': total_chunks}
                self.received_fragments[file_id][chunk_offset] = raw.load[offset:]
                self.log(f"Receiving '{filename}' ({size} bytes), expecting {total_chunks} fragments.", "RECEIVE")
                self.status_label.configure(text=f"Receiving '{filename}'...")
            except Exception as e:
                self.log(f"Metadata parsing error for ID {file_id}: {e}", "ERROR"); return
        else:
            self.received_fragments[file_id][chunk_offset] = raw.load
        
        self.send_ack(client_ip, client_ack_port, file_id, chunk_offset)

        meta = self.file_metadata.get(file_id)
        if meta and len(self.received_fragments[file_id]) == meta['total_chunks']:
            self.log(f"All {meta['total_chunks']} fragments for '{meta['filename']}' received. Reassembling...", "INFO")
            sorted_frags = sorted(self.received_fragments[file_id].items())
            encrypted_data = b''.join([data for offset, data in sorted_frags])
            try:
                key = base64.b64decode(self.base64_key)
                decrypted = unpad(AES.new(key, AES.MODE_CBC, meta['iv']).decrypt(encrypted_data), AES.block_size)
                received_hash = hashlib.sha256(decrypted).digest()
                self.log(f"Received file hash: {received_hash.hex()}", "INFO")
                if received_hash != meta['hash']:
                    self.log(f"Integrity check FAILED for '{meta['filename']}'. Hashes do not match.", "ERROR")
                elif len(decrypted) != meta['size']:
                    self.log(f"File size mismatch for '{meta['filename']}'. Expected {meta['size']}, got {len(decrypted)}.", "ERROR")
                else:
                    self.log(f"Integrity check PASSED for '{meta['filename']}'.", "SUCCESS")
                    os.makedirs(SAVE_FOLDER, exist_ok=True)
                    save_path = os.path.join(SAVE_FOLDER, meta['filename'])
                    with open(save_path, 'wb') as f: f.write(decrypted)
                    self.log(f"Successfully saved '{meta['filename']}' to '{save_path}'.", "SUCCESS")
                    self.status_label.configure(text=f"Last file received: {meta['filename']}")
            except Exception as e:
                self.log(f"Decryption/Save error for '{meta['filename']}': {e}", "ERROR")
            finally:
                if file_id in self.received_fragments: del self.received_fragments[file_id]
                if file_id in self.file_metadata: del self.file_metadata[file_id]
                self.completed_transfers.append(file_id)

if __name__ == "__main__":
    app = ServerApp()
    app.mainloop()