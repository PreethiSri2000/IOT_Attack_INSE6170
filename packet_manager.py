from scapy.sendrecv import sniff
from scapy.utils import wrpcap, rdpcap


def capture_packets(interface, ip, packet_count, output_file):
    print(output_file)
    capture = sniff(iface=str(interface), filter=f"ip host {str(ip)}", count=int(packet_count))
    wrpcap("../" + output_file, capture)


def read_packets(file_name):
    packets = rdpcap("../" + file_name)
    return packets
