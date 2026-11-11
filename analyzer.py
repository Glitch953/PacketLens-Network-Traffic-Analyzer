
from collections import Counter, defaultdict, deque

from scapy.all import (
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    DNS,
    DNSQR,
    DNSRR
)


# ==========================================
# DNS TYPE NAMES
# ==========================================

DNS_TYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    29: "LOC",
    33: "SRV",
    35: "NAPTR",
    39: "DNAME",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    50: "NSEC3",
    52: "TLSA",
    64: "SVCB",
    65: "HTTPS",
    255: "ANY"
}


# ==========================================
# DNS RESPONSE CODE NAMES
# ==========================================

DNS_RESPONSE_CODES = {
    0: "ok",
    1: "formerr",
    2: "servfail",
    3: "nxdomain",
    4: "notimp",
    5: "refused",
    6: "yxdomain",
    7: "xrrset",
    8: "notauth",
    9: "notzone"
}


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def decode_value(value):
    """Convert DNS values into readable strings."""

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    if isinstance(value, list):
        return [decode_value(item) for item in value]

    if isinstance(value, tuple):
        return tuple(decode_value(item) for item in value)

    return value


def get_dns_type_name(type_number):
    """Convert DNS type number into a readable name."""

    return DNS_TYPE_NAMES.get(type_number, str(type_number))


def get_domain(dns):
    """Extract the queried domain from a DNS packet."""

    if dns.qd is None:
        return None

    return decode_value(dns.qd.qname).rstrip(".") + "."


def get_query_type(dns):
    """Extract DNS query type."""

    if dns.qd is None:
        return None

    return int(dns.qd.qtype)


def get_response_code(dns):
    """Extract readable DNS response code."""

    code = int(dns.rcode)

    return DNS_RESPONSE_CODES.get(code, f"unknown_{code}")


def get_packet_endpoints(packet):
    """Extract IP addresses and transport ports."""

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst

    else:
        return None

    if UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    elif TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    else:
        return None

    return src_ip, dst_ip, src_port, dst_port


# ==========================================
# DNS ANSWER EXTRACTION - FIXED
# ==========================================

def extract_dns_answers(dns):
    """Extract all DNS answer records."""

    answers = []

    records = dns.an

    if not records:
        return answers

    # Scapy returns DNS answers as a list.
    for record in records:

        if not isinstance(record, DNSRR):
            continue

        record_type = int(record.type)

        answer = {
            "domain": decode_value(record.rrname),
            "type": get_dns_type_name(record_type),
            "data": decode_value(record.rdata),
            "ttl": int(record.ttl)
        }

        answers.append(answer)

    return answers


# ==========================================
# MAIN ANALYZER
# ==========================================

def analyze_packets(packets):

    # --------------------------------------
    # Protocol Statistics
    # --------------------------------------

    protocol_stats = {
        "TCP": 0,
        "UDP": 0,
        "ICMP": 0,
        "Other": 0,
        "Total": 0
    }

    # --------------------------------------
    # DNS Statistics
    # --------------------------------------

    dns_queries = Counter()

    dns_query_types = Counter()

    dns_response_types = Counter()

    dns_response_code_stats = Counter()

    dns_answers = []

    dns_ip_mapping = defaultdict(set)

    dns_transactions = {}

    pending_transactions = defaultdict(deque)

    transaction_counters = Counter()

    total_dns_packets = 0

    dns_query_count = 0

    dns_response_count = 0

    unmatched_responses = 0

    # ======================================
    # PROCESS PACKETS
    # ======================================

    for packet in packets:

        protocol_stats["Total"] += 1

        # ----------------------------------
        # Protocol Detection
        # ----------------------------------

        if TCP in packet:
            protocol_stats["TCP"] += 1

        elif UDP in packet:
            protocol_stats["UDP"] += 1

        elif ICMP in packet:
            protocol_stats["ICMP"] += 1

        else:
            protocol_stats["Other"] += 1

        # ----------------------------------
        # DNS Detection
        # ----------------------------------

        if DNS not in packet:
            continue

        dns = packet[DNS]

        total_dns_packets += 1

        endpoints = get_packet_endpoints(packet)

        if endpoints is None:
            continue

        src_ip, dst_ip, src_port, dst_port = endpoints

        domain = get_domain(dns)

        query_type = get_query_type(dns)

        if domain is None:
            continue

        # ==================================
        # DNS QUERY
        # ==================================

        if dns.qr == 0:

            dns_query_count += 1

            dns_queries[domain] += 1

            if query_type is not None:
                dns_query_types[
                    get_dns_type_name(query_type)
                ] += 1

            base_key = (
                int(dns.id),
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                domain,
                query_type
            )

            transaction_counters[base_key] += 1

            occurrence = transaction_counters[base_key]

            transaction_key = base_key + (occurrence,)

            dns_transactions[transaction_key] = {
                "transaction_id": int(dns.id),
                "domain": domain,
                "query_type": query_type,
                "response": None
            }

            pending_transactions[base_key].append(
                transaction_key
            )

        # ==================================
        # DNS RESPONSE
        # ==================================

        elif dns.qr == 1:

            dns_response_count += 1

            response_code = int(dns.rcode)

            dns_response_code_stats[
                get_response_code(dns)
            ] += 1

            answers = extract_dns_answers(dns)

            # ----------------------------------
            # Answer Analysis
            # ----------------------------------

            for answer in answers:

                dns_answers.append(answer)

                answer_domain = answer["domain"].rstrip(".") + "."

                answer_type = answer["type"]

                answer_data = answer["data"]

                dns_response_types[answer_type] += 1

                if answer_type in ("A", "AAAA"):

                    dns_ip_mapping[answer_domain].add(
                        answer_data
                    )

            # ----------------------------------
            # Match Response With Query
            # ----------------------------------

            response_base_key = (
                int(dns.id),
                dst_ip,
                src_ip,
                dst_port,
                src_port,
                domain,
                query_type
            )

            pending_queue = pending_transactions.get(
                response_base_key
            )

            if pending_queue:

                transaction_key = pending_queue.popleft()

                dns_transactions[transaction_key]["response"] = {
                    "transaction_id": int(dns.id),
                    "response_code": response_code,
                    "answers": answers
                }

                if not pending_queue:
                    del pending_transactions[response_base_key]

            else:

                unmatched_responses += 1

    # ======================================
    # TRANSACTION STATISTICS
    # ======================================

    total_transactions = len(dns_transactions)

    successful_transactions = 0

    failed_transactions = 0

    no_response_transactions = 0

    for transaction in dns_transactions.values():

        response = transaction["response"]

        if response is None:

            no_response_transactions += 1

        elif response["response_code"] == 0:

            successful_transactions += 1

        else:

            failed_transactions += 1

    dns_transaction_stats = {
        "total_transactions": total_transactions,
        "successful": successful_transactions,
        "failed": failed_transactions,
        "no_response": no_response_transactions,
        "unmatched_responses": unmatched_responses
    }

    # ======================================
    # FINAL RESULTS
    # ======================================

    return {

        "protocol_stats": protocol_stats,

        "total_dns_packets": total_dns_packets,

        "dns_query_count": dns_query_count,

        "dns_response_count": dns_response_count,

        "dns_queries": dns_queries,

        "dns_query_types": dns_query_types,

        "dns_response_types": dns_response_types,

        "dns_response_code_stats": dns_response_code_stats,

        "dns_answers": dns_answers,

        "dns_ip_mapping": {
            domain: sorted(ips)
            for domain, ips in dns_ip_mapping.items()
        },

        "dns_transactions": dns_transactions,

        "dns_transaction_stats": dns_transaction_stats

    }
