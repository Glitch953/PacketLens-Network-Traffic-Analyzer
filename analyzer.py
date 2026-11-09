from scapy.all import TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw

def analyze_packets(packets):
    dns_queries = {}

    protocol_stats = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "DNS":0,
    "DNS_QUERY": 0,
    "DNS_RESPONSE": 0,
    "Other": 0,
    "Total": 0
 }
    dns_types = {

    }
    # Initialize counters for each protocol
    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    other_count = 0
    dns_count = 0

    # Analyze each packet
    for packet in packets:
        if TCP in packet:
            tcp_count += 1
            protocol_stats["TCP"] = tcp_count
        elif UDP in packet:
            udp_count += 1
            protocol_stats["UDP"] = udp_count
        elif ICMP in packet:
            icmp_count += 1
            protocol_stats["ICMP"] = icmp_count
        else:
            other_count += 1
            protocol_stats["Other"] = other_count
        if DNS in packet:
            dns_count+=1
            protocol_stats["DNS"] = dns_count
            if packet[DNS].qr == 0:
                protocol_stats["DNS_QUERY"] += 1
            else:
                protocol_stats["DNS_RESPONSE"] += 1
        if packet.haslayer(DNSQR) and packet[DNS].qr == 0:
            query_name = packet[DNSQR].qname.decode("utf-8",errors="ignore")
            query_type = packet[DNSQR].qtype
            dns_types[query_type] = dns_types.get(query_type, 0) + 1
            dns_queries[query_name] = dns_queries.get(query_name, 0) + 1
    print(f"Unique Domains: {len(dns_queries)}")
    sorted_queries = sorted(dns_queries.items(), reverse=True, key=lambda x: x[1])
    sorted_queries = sorted_queries[:3]
    for query, count in sorted_queries:
         print(f"DNS Query: {query} | Count: {count}")

    for dns_type, count in dns_types.items():
        dns_type_name = DNSQR.fields_desc[1].i2s.get(dns_type, "Unknown")
        print(f"DNS Type: {dns_type_name} | Count: {count}")

    protocol_stats["Total"] = len(packets)
    results = {
        "protocol_stats": protocol_stats,
        "dns_queries": dns_queries,
        "dns_types": dns_types
    }
    return results