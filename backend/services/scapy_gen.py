import os, binascii
from scapy.all import IP, TCP, ICMP, Raw, wrpcap

def _hexdump_bytes(data: bytes, limit=512):
    hx = binascii.hexlify(data[:limit]).decode()
    if len(data) > limit: hx += "...(truncated)"
    return hx

def make_pkt_sqli(src, dst, dport=80, count=10):
    pkts=[]
    payload=b"GET /?q=1 UNION SELECT password FROM users HTTP/1.1\r\nHost: test\r\n\r\n"
    for i in range(count):
        pkts.append(IP(src=src, dst=dst)/TCP(sport=40000+i, dport=dport, flags="PA")/Raw(payload))
    return pkts

def make_pkt_syn(src, dst, dport=80, count=100):
    return [IP(src=src, dst=dst)/TCP(sport=41000+i, dport=dport, flags="S") for i in range(count)]

def make_pkt_icmp(src, dst, count=20):
    return [IP(src=src, dst=dst)/ICMP(id=1234, seq=i) for i in range(count)]

def generate_pcap(template_id: str, variables: dict, out_path: str):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    if template_id == "pkt-sqli":
        pkts = make_pkt_sqli(variables["src_ip"], variables["dst_ip"], variables.get("dst_port",80), variables.get("count",10))
    elif template_id == "pkt-syn":
        pkts = make_pkt_syn(variables["src_ip"], variables["dst_ip"], variables.get("dst_port",80), variables.get("count",100))
    elif template_id == "pkt-icmp":
        pkts = make_pkt_icmp(variables["src_ip"], variables["dst_ip"], variables.get("count",20))
    else:
        raise ValueError("Unknown template")
    wrpcap(out_path, pkts)
    sample = bytes(pkts[0]) if pkts else b""
    return {
        "pcap_path": out_path,
        "packet_count": len(pkts),
        "preview_hex": _hexdump_bytes(sample),
        "preview_summary": f"packets={len(pkts)}"
    }

