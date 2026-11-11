from analyzer import analyze_packets
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR


# Create two identical DNS queries
query_e = (
    IP(src="192.168.1.10", dst="192.168.1.1") /
    UDP(sport=50000, dport=53) /
    DNS(
        id=9999,
        qr=0,
        qd=DNSQR(qname="example.test.", qtype="A")
    )
)

query_f = (
    IP(src="192.168.1.10", dst="192.168.1.1") /
    UDP(sport=50000, dport=53) /
    DNS(
        id=9999,
        qr=0,
        qd=DNSQR(qname="example.test.", qtype="A")
    )
)


# Response E
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
            ttl=300,
            rdata="10.0.0.50"
        )
    )
)


# Response F
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
            ttl=300,
            rdata="10.0.0.60"
        )
    )
)

print("\n========== RAW DNS ANSWER DEBUG ==========")

print("Response E DNS Answer:")
response_e[DNS].an.show()

print("\nResponse F DNS Answer:")
response_f[DNS].an.show()

print("\nAnswer E type:", type(response_e[DNS].an))
print("Answer F type:", type(response_f[DNS].an))

# Test packets (FIFO order)
packets = [
    query_e,
    query_f,
    response_f,
    response_e
]


# Analyze packets
results = analyze_packets(packets)


# Display transaction details
print("\n========== DNS TRANSACTION DETAILS ==========")

for key, transaction in results["dns_transactions"].items():

    print("\nTransaction ID:", transaction["transaction_id"])
    print("Domain:", transaction["domain"])
    print("Query Type:", transaction["query_type"])

    response = transaction["response"]

    if response is None:
        print("Response Code: No Response")
        print("Answer IP: No Answer")

    else:
        print("Response Code:", response["response_code"])

        answers = response["answers"]

        if answers:
            for answer in answers:
                print("Answer IP:", answer["data"])
        else:
            print("Answer IP: No Answer")
