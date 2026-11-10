from scapy.all import rdpcap

def read_capture():
    input_path = input("Enter the path to the pcap file: ")
    try:
        packets = rdpcap(input_path)
    except FileNotFoundError:
        print(f"File not found: {input_path}")
        return []
    except Exception as e:
        print(f"An error occurred while reading the pcap file: {e}")
        return []

    packet_count = 0

    if not packets:
        print("No packets found in the pcap file.")
    else:
        print("Packets read successfully.")
        packet_count = len(packets)

    print(f"Total packets read: {packet_count}")
    return packets

if __name__ == "__main__":
    packets = read_capture()
