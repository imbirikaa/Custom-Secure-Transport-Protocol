import os
import threading
import time
import customtkinter as ctk
from tkinter import filedialog
import base64
import hashlib
from collections import deque
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from scapy.all import IP, UDP, Raw, send, sniff, RandShort, Packet, bind_layers
from scapy.fields import ShortField, IntField

# --- CONFIGURATION FOR KALI LINUX CLIENT ---
LOOPBACK_INTERFACE = "eth0"
SERVER_IP = '192.168.56.1' # IP of the Windows Server
SERVER_DATA_PORT = 5001      # The port on the server we send data to
CLIENT_ACK_PORT = 5002       # The port this client will listen on for ACKs

# region --- SCAPY & APP CONFIG ---
class FileTransferHeader(Packet):
    name = "FileTransferHeader"
    fields_desc = [ShortField("file_id", 0), IntField("chunk_offset", 0), ShortField("flags", 0)]
bind_layers(UDP, FileTransferHeader, dport=SERVER_DATA_PORT)

class ACKHeader(Packet):
    name = "ACKHeader"
    fields_desc = [ShortField("file_id", 0), IntField("acked_offset", 0), ShortField("status", 0)]
bind_layers(UDP, ACKHeader, dport=CLIENT_ACK_PORT)

FLAG_MORE_FRAGMENTS = 0x01
# endregion

class ClientApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.file_path = None
        self.is_key_valid = False
        self.acks_received = {}
        self.transfer_complete = threading.Event()
        self.ack_listener_thread = None
        self.active_transfer_id = None
        self.fragment_widgets = []
        self.ui_update_queue = deque()
        self.title("Secure Transfer Client")
        self.geometry("800x750")
        self.configure(fg_color='#2D2D2D')
        self.resizable(False, False)
        ctk.set_appearance_mode("dark")
        self.create_widgets()
        self.key_entry.bind('<KeyRelease>', self.validate_key_ui)
        self.after(100, self.process_ui_queue)

    def create_widgets(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        self.grid_rowconfigure(3, weight=1)
        header_label = ctk.CTkLabel(self, text="Secure File Transfer Client", font=ctk.CTkFont(size=24, weight="bold"), text_color="#00A9E0")
        header_label.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        controls_frame = ctk.CTkFrame(self, fg_color="transparent")
        controls_frame.grid(row=1, column=0, padx=20, pady=5, sticky="ew")
        controls_frame.grid_columnconfigure(1, weight=1)
        self.key_entry = ctk.CTkEntry(controls_frame, placeholder_text="Enter 32-byte Base64 AES Key", height=35, border_width=1)
        self.key_entry.grid(row=0, column=0, columnspan=3, padx=(0, 20), pady=5, sticky="ew")
        self.select_button = ctk.CTkButton(controls_frame, text="Select File", height=35, command=self.select_file)
        self.select_button.grid(row=1, column=0, padx=(0, 10), pady=10, sticky="w")
        self.send_button = ctk.CTkButton(controls_frame, text="Send File", height=35, command=self.send_file, state="disabled")
        self.send_button.grid(row=1, column=1, padx=0, pady=10, sticky="w")
        self.selected_file_label = ctk.CTkLabel(controls_frame, text="No file selected.", text_color="#A0A0A0", anchor="w")
        self.selected_file_label.grid(row=1, column=2, padx=20, pady=10, sticky="ew")
        map_outer_frame = ctk.CTkFrame(self, fg_color="#242424", border_width=1)
        map_outer_frame.grid(row=2, column=0, padx=20, pady=10, sticky="nsew")
        map_outer_frame.grid_columnconfigure(0, weight=1)
        map_outer_frame.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(map_outer_frame, text="Fragment Map", font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, pady=(5,5))
        self.fragment_map_frame = ctk.CTkScrollableFrame(map_outer_frame, fg_color="#242424")
        self.fragment_map_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        log_progress_frame = ctk.CTkFrame(self, fg_color="transparent")
        log_progress_frame.grid(row=3, column=0, padx=20, pady=(0, 10), sticky="nsew")
        log_progress_frame.grid_rowconfigure(0, weight=1)
        log_progress_frame.grid_columnconfigure(0, weight=1)
        self.log_area = ctk.CTkTextbox(log_progress_frame, font=("Consolas", 11), border_width=1, fg_color="#242424")
        self.log_area.grid(row=0, column=0, sticky="nsew")
        self.log_area.tag_config('SUCCESS', foreground='#4CAF50'); self.log_area.tag_config('ERROR', foreground='#F44336')
        self.log_area.tag_config('INFO', foreground='#2196F3'); self.log_area.tag_config('WARN', foreground='#FFC107')
        self.progress_bar = ctk.CTkProgressBar(log_progress_frame, height=8); self.progress_bar.set(0)
        self.progress_bar.grid(row=1, column=0, padx=0, pady=(10, 0), sticky="ew")
        self.status_label = ctk.CTkLabel(self, text="Idle", text_color="#A0A0A0", height=25, anchor="w")
        self.status_label.grid(row=4, column=0, padx=20, pady=(0, 10), sticky="ew")

    def process_ui_queue(self):
        for _ in range(len(self.ui_update_queue)):
            if not self.ui_update_queue: break
            func, args = self.ui_update_queue.popleft()
            func(*args)
        self.after(50, self.process_ui_queue)

    def log(self, message, level='INFO'):
        self.ui_update_queue.append((self._log_task, (message, level)))
    def _log_task(self, message, level):
        timestamp = time.strftime('%H:%M:%S')
        self.log_area.insert("end", f"[{timestamp}] ", "normal")
        self.log_area.insert("end", f"[{level}] ", (level.upper(),))
        self.log_area.insert("end", f"{message}\n", "normal")
        self.log_area.see("end")

    def setup_fragment_map(self, total_chunks):
        for widget in self.fragment_widgets: widget.destroy()
        self.fragment_widgets.clear(); self.update_idletasks()
        frame_width = self.fragment_map_frame.winfo_width()
        box_size, gap = 8, 2
        cols = max(1, (frame_width - gap) // (box_size + gap))
        for i in range(total_chunks):
            row, col = divmod(i, cols)
            box = ctk.CTkFrame(self.fragment_map_frame, width=box_size, height=box_size, fg_color="#404040", corner_radius=2, border_width=0)
            box.grid(row=row, column=col, padx=gap//2, pady=gap//2)
            self.fragment_widgets.append(box)

    def update_fragment_map(self, index, status):
        color_map = {"sent": "#2196F3", "acked": "#4CAF50", "retrans": "#F44336"}
        if index < len(self.fragment_widgets):
            self.fragment_widgets[index].configure(fg_color=color_map.get(status, "#404040"))

    def validate_key_ui(self, event=None):
        try:
            self.is_key_valid = len(base64.b64decode(self.key_entry.get().strip())) == 32
        except Exception: self.is_key_valid = False
        self.key_entry.configure(border_color="#4CAF50" if self.is_key_valid else "#F44336")
        self.update_send_button_state()

    def update_send_button_state(self):
        self.send_button.configure(state="normal" if self.is_key_valid and self.file_path else "disabled")

    def select_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            self.selected_file_label.configure(text=os.path.basename(self.file_path))
            self.log(f"File selected: {os.path.basename(self.file_path)}", "INFO")
        else:
            self.selected_file_label.configure(text="No file selected.")
        self.validate_key_ui()

    def send_file(self):
        self.progress_bar.set(0); self.status_label.configure(text="Preparing to send...")
        key_b64 = self.key_entry.get().strip()
        filename_bytes = os.path.basename(self.file_path).encode()
        with open(self.file_path, 'rb') as f: data = f.read()
        self.transfer_complete.clear()
        if not (self.ack_listener_thread and self.ack_listener_thread.is_alive()):
            self.ack_listener_thread = threading.Thread(target=self._ack_listener, daemon=True)
            self.ack_listener_thread.start()
        threading.Thread(target=self._send_file_threaded, args=(key_b64, filename_bytes, data), daemon=True).start()

    def _send_file_threaded(self, key_b64, filename_bytes, file_data):
        try:
            file_hash = hashlib.sha256(file_data).digest()
            self.log(f"Original file hash (SHA-256): {file_hash.hex()}", "INFO")
            original_file_size = len(file_data)
            iv, encrypted_data = self.encrypt_data(base64.b64decode(key_b64), file_data)
            self.send_file_reliable(filename_bytes, original_file_size, iv, file_hash, encrypted_data)
        except Exception as e:
            self.log(f"File sending failed: {e}", "ERROR")
            self.status_label.configure(text=f"Error: {e}")

    def encrypt_data(self, key, data):
        iv = get_random_bytes(AES.block_size); cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv, cipher.encrypt(pad(data, AES.block_size))

    def _ack_listener(self):
        self.log(f"ACK listener started on interface '{LOOPBACK_INTERFACE}'.", "INFO")
        try:
            sniff(iface=LOOPBACK_INTERFACE, filter=f"udp and dst port {CLIENT_ACK_PORT}",
                  prn=self._handle_ack_packet, stop_filter=lambda p: self.transfer_complete.is_set(), store=0)
        except Exception as e:
            self.log(f"ACK listener error: {e}. Is the interface name correct?", "ERROR")
        self.log("ACK listener stopped.", "INFO")

    def _handle_ack_packet(self, packet):
        if ACKHeader in packet:
            ack = packet[ACKHeader]
            if ack.file_id == self.active_transfer_id and ack.file_id in self.acks_received:
                self.acks_received[ack.file_id].add(ack.acked_offset)

    def send_file_reliable(self, filename_bytes, original_file_size, iv, file_hash, encrypted_data):
        key_b64 = self.key_entry.get()
        UDP_PAYLOAD_SIZE = 1400
        metadata_header_len = len(key_b64) + len(iv) + len(filename_bytes) + 32 + 8 + 4*4
        first_enc_data = encrypted_data[:UDP_PAYLOAD_SIZE - metadata_header_len]
        chunks = [{'payload': first_enc_data, 'offset': 0}]
        rem_enc_data = encrypted_data[len(first_enc_data):]
        offset = len(first_enc_data)
        for i in range(0, len(rem_enc_data), UDP_PAYLOAD_SIZE):
            chunk_data = rem_enc_data[i:i + UDP_PAYLOAD_SIZE]
            chunks.append({'payload': chunk_data, 'offset': offset})
            offset += len(chunk_data)
        total_chunks = len(chunks)
        
        metadata = (len(key_b64).to_bytes(4, 'big') + key_b64.encode() + len(iv).to_bytes(4, 'big') + iv +
                    len(filename_bytes).to_bytes(4, 'big') + filename_bytes + original_file_size.to_bytes(8, 'big') + 
                    file_hash + total_chunks.to_bytes(4, 'big'))
        chunks[0]['payload'] = metadata + chunks[0]['payload']

        self.active_transfer_id = int(RandShort())
        self.acks_received[self.active_transfer_id] = set()
        self.after(0, self.setup_fragment_map, total_chunks)
        self.log(f"Sending '{filename_bytes.decode()}' in {total_chunks} fragments (ID: {self.active_transfer_id}).", "INFO")
        self.status_label.configure(text=f"Sending {os.path.basename(self.file_path)}...")

        RTO, MAX_RETRIES, window_size = 0.5, 5, 40
        window, next_idx, acked_count, rtt_samples = [], 0, 0, []
        acked_offsets_for_ui = set()
        transfer_start_time = time.time()
        
        while acked_count < total_chunks:
            while len(window) < window_size and next_idx < total_chunks:
                info, chunk_index = chunks[next_idx], next_idx
                flags = FLAG_MORE_FRAGMENTS if chunk_index < total_chunks - 1 else 0
                
                packet = (IP(dst=SERVER_IP, ttl=64) /
                          UDP(sport=CLIENT_ACK_PORT, dport=SERVER_DATA_PORT) /
                          FileTransferHeader(file_id=self.active_transfer_id, chunk_offset=info['offset'], flags=flags) /
                          Raw(load=info['payload']))
                
                send(packet, iface=LOOPBACK_INTERFACE, verbose=0)
                
                self.ui_update_queue.append((self.update_fragment_map, (chunk_index, "sent")))
                window.append({'pkt': packet, 'offset': info['offset'], 'idx': chunk_index, 'time': time.time(), 'retries': 0})
                next_idx += 1

            new_window = []
            current_time = time.time()
            for item in window:
                if item['offset'] in self.acks_received[self.active_transfer_id] and item['offset'] not in acked_offsets_for_ui:
                    rtt = current_time - item['time']; rtt_samples.append(rtt)
                    acked_count += 1; acked_offsets_for_ui.add(item['offset'])
                    self.ui_update_queue.append((self.update_fragment_map, (item['idx'], "acked")))
                    self.ui_update_queue.append((self.update_progress, (acked_count, total_chunks)))
                    continue
                
                if current_time - item['time'] > RTO:
                    if item['retries'] < MAX_RETRIES:
                        send(item['pkt'], iface=LOOPBACK_INTERFACE, verbose=0)
                        self.ui_update_queue.append((self.update_fragment_map, (item['idx'], "retrans")))
                        item['time'] = current_time; item['retries'] += 1
                        new_window.append(item)
                    else:
                        self.log(f"Max retries for offset {item['offset']}. Transfer failed.", "ERROR")
                        self.status_label.configure(text="Transfer Failed: Max Retries"); self.transfer_complete.set(); return
                elif item['offset'] not in acked_offsets_for_ui:
                    new_window.append(item)
            window = new_window
            if next_idx == total_chunks and not window: break
            time.sleep(0.005)

        transfer_end_time = time.time()
        self.log("File transfer successful!", "SUCCESS")
        self.status_label.configure(text="Transfer Complete")
        self.progress_bar.set(1.0)
        
        if rtt_samples:
            min_rtt, max_rtt, avg_rtt = min(rtt_samples)*1000, max(rtt_samples)*1000, (sum(rtt_samples)/len(rtt_samples))*1000
            self.log(f"RTT Stats: Min={min_rtt:.2f}ms, Avg={avg_rtt:.2f}ms, Max={max_rtt:.2f}ms", "INFO")
        total_time = transfer_end_time - transfer_start_time
        if total_time > 0:
            bandwidth_mbps = (original_file_size * 8) / (total_time * 1000 * 1000)
            self.log(f"Transfer Time: {total_time:.2f} seconds", "INFO")
            self.log(f"Effective Bandwidth: {bandwidth_mbps:.2f} Mbps", "INFO")
        self.transfer_complete.set()
        if self.active_transfer_id in self.acks_received: del self.acks_received[self.active_transfer_id]
        self.active_transfer_id = None

    def update_progress(self, current, total):
        if total > 0: self.progress_bar.set(current / total)

if __name__ == "__main__":
    app = ClientApp()
    app.mainloop()