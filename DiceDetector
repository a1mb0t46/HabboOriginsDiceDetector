from scapy.all import sniff, TCP, Raw

ports = [58463, 40001]

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw) and (packet[TCP].sport in ports or packet[TCP].dport in ports):
        payload = packet[Raw].load
        if b'edice' in payload:
            try:
                decoded_payload = payload.decode('utf-8')
                parts = decoded_payload.split('\x02')
                if 'A' in parts[0]:
                    split_result = parts[0].split('A')
                    if len(split_result) > 1:
                        item_id = split_result[1]
                        action_symbol = item_id[0]
                        item_id = item_id[1:]
                        item_name = parts[1]
                        
                        actions = {'^': 'picked up', ']': 'placed', '_': 'moved'}
                        action = actions.get(action_symbol, 'unknown')
                        
                        print(f"Action: {action}, Item ID: {item_id}, Item Name: {item_name}")
                    else:
                        print("Error: 'A' not followed by an ID in the payload.")
                else:
                    print("Error: 'A' not found in the payload.")
            except UnicodeDecodeError:
                print("Payload could not be decoded to UTF-8.")
            print("\n")

sniff(filter="tcp", prn=packet_callback, store=0)
