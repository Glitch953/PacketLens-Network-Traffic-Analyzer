
from scapy.all import TCP, UDP, ICMP, DNS, DNSQR, DNSRR


def decode_value(value):
    """Convert DNS values into readable strings."""

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    if isinstance(value, list):
        return [decode_value(item) for item in value]

    if isinstance(value, tuple):
        return tuple(decode_value(item) for item in value)

    return value


def analyze_packets(packets):

    dns_queries = {}
    dns_answers = []
    dns_ip_mapping = {}
    dns_transactions = {}

    dns_transaction_stats = {
        "total_transactions": 0,
        "successful": 0,
        "failed": 0,
        "no_response": 0,
        "unmatched_responses": 0
    }

    dns_response_code_stats = {}

    dns_query_types = {}
    dns_response_types = {}

    # Get DNS Response Code field
    rcode_field = next(
        field for field in DNS.fields_desc
        if field.name == "rcode"
    )

    protocol_stats = {
        "TCP": 0,
        "UDP": 0,
        "ICMP": 0,
        "DNS": 0,
        "DNS_QUERY": 0,
        "DNS_RESPONSE": 0,
        "Other": 0,
        "Total": 0
    }

    # Analyze each packet
    for packet in packets:

        # Protocol Analysis
        if TCP in packet:
            protocol_stats["TCP"] += 1

        elif UDP in packet:
            protocol_stats["UDP"] += 1

        elif ICMP in packet:
            protocol_stats["ICMP"] += 1

        else:
            protocol_stats["Other"] += 1

        # Check DNS
        if DNS not in packet:
            continue

        dns = packet[DNS]
        protocol_stats["DNS"] += 1

        # DNS Query Analysis
        if dns.qr == 0 and dns.qd:

            transaction_id = dns.id

            domain = decode_value(dns.qd.qname)
            query_type = dns.qd.qtype

            dns_transactions[transaction_id] = {
                "domain": domain,
                "query_type": query_type,
                "response": None
            }

            protocol_stats["DNS_QUERY"] += 1

            if packet.haslayer(DNSQR):

                query_name = decode_value(packet[DNSQR].qname)
                query_type = packet[DNSQR].qtype

                dns_queries[query_name] = (
                    dns_queries.get(query_name, 0) + 1
                )

                dns_query_types[query_type] = (
                    dns_query_types.get(query_type, 0) + 1
                )

        # DNS Response Analysis
        elif dns.qr == 1:

            protocol_stats["DNS_RESPONSE"] += 1

            transaction_id = dns.id

            transaction = dns_transactions.get(transaction_id)

            # Count DNS Response Codes
            dns_response_code_stats[dns.rcode] = (
                dns_response_code_stats.get(dns.rcode, 0) + 1
            )

            if transaction is None:
                dns_transaction_stats["unmatched_responses"] += 1
                continue

            transaction["response"] = {
                "transaction_id": dns.id,
                "response_code": dns.rcode,
                "answers": []
            }

            if dns.ancount > 0 and dns.an:

                record = dns.an

                for _ in range(dns.ancount):

                    # Check whether this is an Answer Record
                    if not hasattr(record, "rrname") or not hasattr(record, "type"):
                        break

                    # Extract record information
                    record_name = decode_value(record.rrname)
                    record_type = record.type

                    # Convert record type number to readable name
                    record_type_name = DNSRR.fields_desc[1].i2s.get(
                        record_type, "Unknown"
                    )

                    # Extract record data
                    record_data = record.fields.get("rdata")

                    # Handle records such as MX
                    if record_data is None:
                        record_data = record.fields.get("exchange")

                    record_data = decode_value(record_data)

                    # Extract MX preference if available
                    preference = record.fields.get("preference")

                    if preference is not None:
                        record_data = {
                            "preference": preference,
                            "exchange": record_data
                        }

                    # Store Answer Record
                    answer = {
                        "name": record_name,
                        "type": record_type_name,
                        "data": record_data
                    }

                    dns_answers.append(answer)

                    transaction["response"]["answers"].append(answer)

                    # Map IP addresses to domain names for A and AAAA records
                    if record_type in [1, 28]:

                        if record_name not in dns_ip_mapping:
                            dns_ip_mapping[record_name] = []

                        if record_data not in dns_ip_mapping[record_name]:
                            dns_ip_mapping[record_name].append(record_data)

                    # Count DNS Response Types
                    dns_response_types[record_type] = (
                        dns_response_types.get(record_type, 0) + 1
                    )

                    # Move to the next Answer Record
                    record = record.payload

    # DNS Transaction Statistics
    if len(dns_transactions) > 0:

        dns_transaction_stats["total_transactions"] = len(dns_transactions)

        for transaction in dns_transactions.values():

            if transaction["response"] is None:
                dns_transaction_stats["no_response"] += 1

            elif transaction["response"]["response_code"] == 0:
                dns_transaction_stats["successful"] += 1

            else:
                dns_transaction_stats["failed"] += 1

    # Total packets
    protocol_stats["Total"] = len(packets)

    # Display Protocol Statistics
    print("\n========== Protocol Statistics ==========")

    for protocol, count in protocol_stats.items():
        print(f"{protocol}: {count}")

    # Unique Domains
    print("\n========== Unique Domains ==========")
    print(len(dns_queries))

    # Top 3 DNS Queries
    print("\n========== Top 3 DNS Queries ==========")

    sorted_queries = sorted(
        dns_queries.items(),
        key=lambda x: x[1],
        reverse=True
    )[:3]

    for query, count in sorted_queries:
        print(f"{query} | Count: {count}")

    # DNS Query Types
    print("\n========== DNS Query Types ==========")

    for dns_type, count in dns_query_types.items():

        type_name = DNSQR.fields_desc[1].i2s.get(
            dns_type, "Unknown"
        )

        print(f"{type_name}: {count}")

    # DNS Response Types
    print("\n========== DNS Response Types ==========")

    for dns_type, count in dns_response_types.items():

        type_name = DNSRR.fields_desc[1].i2s.get(
            dns_type, "Unknown"
        )

        print(f"{type_name}: {count}")

    # DNS Response Code Statistics
    print("\n========== DNS Response Code Statistics ==========")

    for response_code, count in dns_response_code_stats.items():

        response_code_name = rcode_field.i2s.get(
            response_code, "Unknown"
        )

        print(f"{response_code_name}: {count}")

    # DNS Answer Records
    print("\n========== DNS Answer Records ==========")

    for answer in dns_answers:

        print(
            f"Domain: {answer['name']} | "
            f"Type: {answer['type']} | "
            f"Data: {answer['data']}"
        )

    # DNS IP Mapping
    print("\n========== DNS IP Mapping ==========")

    for domain, ips in dns_ip_mapping.items():

        print(f"\nDomain: {domain}")

        for ip in ips:
            print(f"    IP: {ip}")

    # DNS Transactions
    print("\n========== DNS Transactions ==========")

    for transaction_id, transaction in dns_transactions.items():

        print(f"\nTransaction ID: {transaction_id}")
        print(f"Domain: {transaction['domain']}")
        print(f"Query Type: {transaction['query_type']}")

        if transaction["response"] is not None:

            print("Response: Matched")

            print(
                f"Response Code: "
                f"{transaction['response']['response_code']}"
            )

            print("Answers:")

            for answer in transaction["response"]["answers"]:
                print(
                    f"  {answer['name']} | "
                    f"{answer['type']} | "
                    f"{answer['data']}"
                )

        else:
            print("Response: Not Found")

    # DNS Transaction Statistics
    print("\n========== DNS Transaction Statistics ==========")

    print("Total Transactions:", dns_transaction_stats["total_transactions"])
    print("Successful Transactions:", dns_transaction_stats["successful"])
    print("Failed Transactions:", dns_transaction_stats["failed"])
    print("No Response Transactions:", dns_transaction_stats["no_response"])
    print("Unmatched Responses:", dns_transaction_stats["unmatched_responses"])

    # Return Results
    results = {
        "protocol_stats": protocol_stats,
        "dns_queries": dns_queries,
        "dns_query_types": dns_query_types,
        "dns_response_types": dns_response_types,
        "dns_response_code_stats": dns_response_code_stats,
        "dns_answers": dns_answers,
        "dns_ip_mapping": dns_ip_mapping,
        "dns_transactions": dns_transactions,
        "dns_transaction_stats": dns_transaction_stats
    }

    return results
