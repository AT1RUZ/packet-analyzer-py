from dissectors.a_link_layer.ethernet import *

def get_dissectors_list():
    return [
        ('link_layer_types', 'eth', EthernetDissector),
        ('ether_types', 0x0800, IPv4Dissector),
        ('ether_types', 0x86DD, IPv6Dissector),
        ('ether_types', 0x0806, ARPDissector),
        ('ip_proto_types', 6, TCPDissector),
        ('ip_proto_types', 17, UDPDissector),
        ('tcp_port_types', 80, HTTPDissector),
        ('tcp_port_types', 21, FTPDissector),
        ('tcp_port_types', 20, FTPDissector),
        ('udp_port_types', 1900, SSDPDissector),
        ('udp_port_types', 53, DNSDissector),
    ]