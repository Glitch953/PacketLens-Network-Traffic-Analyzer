from pcap_reader import read_capture
from analyzer import analyze_packets

# Read the PCAP file
packets = read_capture()

# Analyze packets
if packets:
    results = analyze_packets(packets)

    # Display analysis results
    print("\nProtocol Analysis")
    print("-----------------")

    for protocol, count in results["protocol_stats"].items():
        print(f"{protocol}: {count}")
    for query, count in results["dns_queries"].items():
        print(f"DNS Query: {query} | Count: {count}")
