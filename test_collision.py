
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR

from analyzer import analyze_packets


# =========================
# Query A
# =========================
query_a = (
    IP(src="192.168.1.10", dst="192.168.1.1") /
    UDP(sport=50000, dport=53) /
    DNS(
        id=1234,
        qr=0,
        qd=DNSQR(qname="client-a.test.", qtype="A")
    )
)


# =========================
# Query B
# =========================
query_b = (
    IP(src="192.168.1.20", dst="192.168.1.1") /
    UDP(sport=50001, dport=53) /
    DNS(
        id=1234,
        qr=0,
        qd=DNSQR(qname="client-b.test.", qtype="A")
    )
)


# =========================
# Query C
# =========================
query_c = (
    IP(src="192.168.1.10", dst="192.168.1.1") /
    UDP(sport=50000, dport=53) /
    DNS(
        id=5678,
        qr=0,
        qd=DNSQR(qname="client-c.test.", qtype="A")
    )
)


# =========================
# Query D
# =========================
query_d = (
    IP(src="192.168.1.10", dst="192.168.1.1") /
    UDP(sport=50000, dport=53) /
    DNS(
        id=5678,
        qr=0,
        qd=DNSQR(qname="beta.test.", qtype="A")
    )
)


# =========================
# Query E
# =========================
query_e = (
    IP(src="192.168.1.10", dst="192.168.1.1") /
    UDP(sport=50000, dport=53) /
    DNS(
        id=9999,
        qr=0,
        qd=DNSQR(qname="example.test.", qtype="A")
    )
)


# =========================
# Query F
# =========================
query_f = (
    IP(src="192.168.1.10", dst="192.168.1.1") /
    UDP(sport=50000, dport=53) /
    DNS(
        id=9999,
        qr=0,
        qd=DNSQR(qname="example.test.", qtype="A")
    )
)


# =========================
# Response A
# =========================
response_a = (
    IP(src="192.168.1.1", dst="192.168.1.10") /
    UDP(sport=53, dport=50000) /
    DNS(
        id=1234,
        qr=1,
        qd=DNSQR(qname="client-a.test.", qtype="A"),
        ancount=1,
        an=DNSRR(
            rrname="client-a.test.",
            type="A",
            rclass="IN",
            ttl=300,
            rdata="10.0.0.10"
        )
    )
)


# =========================
# Response B
# =========================
response_b = (
    IP(src="192.168.1.1", dst="192.168.1.20") /
    UDP(sport=53, dport=50001) /
    DNS(
        id=1234,
        qr=1,
        qd=DNSQR(qname="client-b.test.", qtype="A"),
        ancount=1,
        an=DNSRR(
            rrname="client-b.test.",
            type="A",
            rclass="IN",
            ttl=300,
            rdata="10.0.0.20"
        )
    )
)


# =========================
# Response C
# =========================
response_c = (
    IP(src="192.168.1.1", dst="192.168.1.10") /
    UDP(sport=53, dport=50000) /
    DNS(
        id=5678,
        qr=1,
        qd=DNSQR(qname="client-c.test.", qtype="A"),
        ancount=1,
        an=DNSRR(
            rrname="client-c.test.",
            type="A",
            rclass="IN",
            ttl=300,
            rdata="10.0.0.30"
        )
    )
)


# =========================
# Response D
# =========================
response_d = (
    IP(src="192.168.1.1", dst="192.168.1.10") /
    UDP(sport=53, dport=50000) /
    DNS(
        id=5678,
        qr=1,
        qd=DNSQR(qname="beta.test.", qtype="A"),
        ancount=1,
        an=DNSRR(
            rrname="beta.test.",
            type="A",
            rclass="IN",
            ttl=300,
            rdata="10.0.0.40"
        )
    )
)


# =========================
# Response E
# =========================
response_e = (
    IP(src="192.168.1.1", dst="192.168.1.10") /
    UDP(sport=53, dport=50000) /
    DNS(
        id=9999,
        qr=1,
        qd=DNSQR(qname="example.test.", qtype="A"),
        ancount=1,
        an=DNSRR(
            rrname="example.test.",
            type="A",
            rclass="IN",
            ttl=300,
            rdata="10.0.0.50"
        )
    )
)


# =========================
# Response F
# =========================
response_f = (
    IP(src="192.168.1.1", dst="192.168.1.10") /
    UDP(sport=53, dport=50000) /
    DNS(
        id=9999,
        qr=1,
        qd=DNSQR(qname="example.test.", qtype="A"),
        ancount=1,
        an=DNSRR(
            rrname="example.test.",
            type="A",
            rclass="IN",
            ttl=300,
            rdata="10.0.0.60"
        )
    )
)


# =========================
# Packets
# =========================
packets = [
    query_a,
    query_b,
    response_b,
    response_a,

    query_c,
    query_d,
    response_d,
    response_c,

    # Repeated Identical DNS Queries
    query_e,
    query_f,
    response_f,
    response_e
]


# =========================
# Analyze Packets
# =========================
results = analyze_packets(packets)


# =========================
# Display Results
# =========================
stats = results["dns_transaction_stats"]

print("\n========== DNS COLLISION TEST ==========")

print("Total Transactions:", stats["total_transactions"])
print("Successful Transactions:", stats["successful"])
print("Failed Transactions:", stats["failed"])
print("No Response:", stats["no_response"])
print("Unmatched Responses:", stats["unmatched_responses"])


print("\n========== TRANSACTION DETAILS ==========")

for transaction in results["dns_transactions"]:
    print(transaction)
