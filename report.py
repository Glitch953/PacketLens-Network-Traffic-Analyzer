
DNS_TYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    29: "LOC",
    33: "SRV",
    255: "ALL"
}

DNS_RESPONSE_CODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED"
}


def get_value(item, *keys, default="Unknown"):
    """Get a value using the first matching key."""

    if isinstance(item, dict):
        for key in keys:
            if key in item:
                return item[key]

    return default


def get_dns_type_label(value):
    """Accept either a numeric DNS type or its textual name."""
    if isinstance(value, str):
        return value.upper()
    return DNS_TYPE_NAMES.get(value, f"Unknown ({value})")


def get_dns_response_code_label(value):
    """Accept numeric Scapy codes or textual analyzer labels."""
    if isinstance(value, str):
        normalized = value.lower()
        textual_codes = {
            "ok": "NOERROR",
            "noerror": "NOERROR",
            "formerr": "FORMERR",
            "servfail": "SERVFAIL",
            "nxdomain": "NXDOMAIN",
            "notimp": "NOTIMP",
            "refused": "REFUSED",
            "yxdomain": "YXDOMAIN",
            "xrrset": "YXRRSET",
            "notauth": "NOTAUTH",
            "notzone": "NOTZONE"
        }
        return textual_codes.get(normalized, value.upper())
    return DNS_RESPONSE_CODES.get(value, f"Unknown ({value})")


def generate_report(results, output_path):

    # Get analysis results
    protocol_stats = results["protocol_stats"]
    dns_queries = results["dns_queries"]
    dns_query_types = results["dns_query_types"]
    dns_response_types = results["dns_response_types"]
    dns_response_code_stats = results["dns_response_code_stats"]
    dns_answers = results["dns_answers"]
    dns_ip_mapping = results["dns_ip_mapping"]
    dns_transactions = results["dns_transactions"]
    dns_transaction_stats = results["dns_transaction_stats"]

    report_content = ""

    # ==========================================
    # Report Header
    # ==========================================

    report_content += "==========================================\n"
    report_content += "       PacketLens - Network Analyzer\n"
    report_content += "==========================================\n\n"

    # ==========================================
    # Protocol Statistics
    # ==========================================

    report_content += "========== Protocol Statistics ==========\n"

    for protocol, count in protocol_stats.items():
        report_content += f"{protocol}: {count}\n"

    report_content += "\n"

    # ==========================================
    # DNS Summary
    # ==========================================

    report_content += "========== DNS Summary ==========\n"

    report_content += (
        f"Total DNS Queries: {results.get('dns_query_count', 0)}\n"
    )

    report_content += (
        f"Total DNS Responses: {results.get('dns_response_count', 0)}\n"
    )

    report_content += f"Unique Domains: {len(dns_queries)}\n"

    report_content += (
        f"Successful Transactions: "
        f"{dns_transaction_stats.get('successful', 0)}\n"
    )

    report_content += (
        f"Failed Transactions: "
        f"{dns_transaction_stats.get('failed', 0)}\n"
    )

    report_content += (
        f"No Response Transactions: "
        f"{dns_transaction_stats.get('no_response', 0)}\n"
    )

    # Most Queried Domain
    if dns_queries:

        max_count = max(dns_queries.values())

        most_queried = [
            domain
            for domain, count in dns_queries.items()
            if count == max_count
        ]

        report_content += (
            f"Most Queried Domain: {', '.join(most_queried)} "
            f"({max_count} queries)\n"
        )

    # Most Used Query Type
    if dns_query_types:

        max_count = max(dns_query_types.values())

        most_used_types = [
            get_dns_type_label(query_type)
            for query_type, count in dns_query_types.items()
            if count == max_count
        ]

        report_content += (
            f"Most Used Query Type: {', '.join(most_used_types)} "
            f"({max_count} queries)\n"
        )

    report_content += "\n"

    # ==========================================
    # DNS Basic Statistics
    # ==========================================

    report_content += "========== DNS Basic Statistics ==========\n"

    report_content += (
        f"Total DNS Packets: {results.get('total_dns_packets', 0)}\n"
    )

    report_content += f"Unique Domains: {len(dns_queries)}\n"
    report_content += f"DNS Answer Records: {len(dns_answers)}\n"
    report_content += f"DNS IP Mappings: {len(dns_ip_mapping)}\n"

    report_content += "\n"

    # ==========================================
    # DNS Query Analysis
    # ==========================================

    report_content += "========== DNS Query Analysis ==========\n"

    report_content += "\n--- Top 3 DNS Queries ---\n"

    if dns_queries:

        sorted_queries = sorted(
            dns_queries.items(),
            key=lambda item: item[1],
            reverse=True
        )

        for domain, count in sorted_queries[:3]:
            report_content += f"{domain}: {count}\n"

    else:
        report_content += "No DNS queries found.\n"

    report_content += "\n--- DNS Query Types ---\n"

    if dns_query_types:

        for query_type, count in dns_query_types.items():

            type_name = get_dns_type_label(query_type)

            report_content += f"{type_name}: {count}\n"

    else:
        report_content += "No DNS query types found.\n"

    report_content += "\n"

    # ==========================================
    # DNS Response Analysis
    # ==========================================

    report_content += "========== DNS Response Analysis ==========\n"

    report_content += "\n--- DNS Response Types ---\n"

    if dns_response_types:

        for response_type, count in dns_response_types.items():

            type_name = get_dns_type_label(response_type)

            report_content += f"{type_name}: {count}\n"

    else:
        report_content += "No DNS response types found.\n"

    report_content += "\n--- DNS Response Code Statistics ---\n"

    if dns_response_code_stats:

        for response_code, count in dns_response_code_stats.items():

            code_name = get_dns_response_code_label(response_code)

            report_content += f"{code_name}: {count}\n"

    else:
        report_content += "No DNS response codes found.\n"

    report_content += "\n"

    # ==========================================
    # DNS Answer Records
    # ==========================================

    report_content += "========== DNS Answer Records ==========\n"

    if dns_answers:

        for answer in dns_answers:

            domain = get_value(
                answer,
                "name",
                "domain",
                "Domain"
            )

            record_type = get_value(
                answer,
                "type",
                "Type"
            )

            data = get_value(
                answer,
                "data",
                "Data"
            )

            report_content += f"Domain: {domain}\n"
            report_content += f"Type: {record_type}\n"
            report_content += f"Data: {data}\n"
            report_content += "------------------------------------------\n"

    else:
        report_content += "No DNS answer records found.\n"

    report_content += "\n"

    # ==========================================
    # DNS IP Mapping
    # ==========================================

    report_content += "========== DNS IP Mapping ==========\n"

    if dns_ip_mapping:

        for domain, ip_addresses in dns_ip_mapping.items():

            report_content += f"Domain: {domain}\n"

            if isinstance(ip_addresses, (list, tuple, set)):

                for ip_address in ip_addresses:
                    report_content += f"  IP: {ip_address}\n"

            else:
                report_content += f"  IP: {ip_addresses}\n"

            report_content += "\n"

    else:
        report_content += "No DNS IP mappings found.\n"

    report_content += "\n"

    # ==========================================
    # DNS Transactions
    # ==========================================

    report_content += "========== DNS Transactions ==========\n"

    if dns_transactions:

        for transaction_key, transaction in dns_transactions.items():

            # Get original DNS Transaction ID
            transaction_id = transaction.get(
                "transaction_id",
                transaction_key[0]
                if isinstance(transaction_key, tuple)
                else transaction_key
            )

            domain = transaction["domain"]
            query_type = transaction["query_type"]
            response = transaction["response"]

            query_type_name = get_dns_type_label(query_type)

            report_content += f"Transaction ID: {transaction_id}\n"
            report_content += f"Domain: {domain}\n"

            report_content += (
                f"Query Type: {query_type_name} ({query_type})\n"
            )

            if response is not None:

                report_content += "Response: Matched\n"

                response_code = response["response_code"]

                response_code_name = get_dns_response_code_label(response_code)

                report_content += (
                    f"Response Code: {response_code_name}\n"
                )

                report_content += "Answers:\n"

                if response["answers"]:

                    for answer in response["answers"]:

                        # FIX: Support both "name" and "domain"
                        domain = get_value(
                            answer,
                            "name",
                            "domain",
                            "Domain"
                        )

                        record_type = get_value(
                            answer,
                            "type",
                            "Type"
                        )

                        data = get_value(
                            answer,
                            "data",
                            "Data"
                        )

                        report_content += (
                            f"  {domain} | "
                            f"{record_type} | "
                            f"{data}\n"
                        )

                else:
                    report_content += "  No Answer Records\n"

            else:

                report_content += "Response: Not Found\n"
                report_content += "Answers: None\n"

            report_content += "------------------------------------------\n"

    else:
        report_content += "No DNS transactions found.\n"

    report_content += "\n"

    # ==========================================
    # DNS Transaction Statistics
    # ==========================================

    report_content += "========== DNS Transaction Statistics ==========\n"

    for stat_name, count in dns_transaction_stats.items():

        readable_name = stat_name.replace("_", " ").title()

        report_content += f"{readable_name}: {count}\n"

    report_content += "\n"

    # ==========================================
    # Save Report
    # ==========================================

    import os
    output_directory = os.path.dirname(output_path)
    if output_directory:
        os.makedirs(output_directory, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as report_file:

        report_file.write(report_content)

    print(f"Report saved successfully: {output_path}")
