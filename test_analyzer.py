from report import generate_report
from pcap_reader import read_capture
from analyzer import analyze_packets

# Read the PCAP file
packets = read_capture()

# Analyze packets
if packets:
    results = analyze_packets(packets)
    generate_report(results, "reports/dns_report.txt")
    print("Report generated successfully!")
