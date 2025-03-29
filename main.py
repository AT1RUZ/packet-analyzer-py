from core.packet import Packet
from core.registry import *
from dissectors.a_link_layer.ethernet import EthernetDissector

import numpy as np
import pyshark
import streamlit as st

def pcap_to_array(packet):
    print("DENTRO DE PCAP TO ARRAY")
    print(packet)
    return pyshark.FileCapture(packet)


def analyze_packet(raw_data):
    packet = Packet(raw_data)
    current_dissector = EthernetDissector()
    payload = raw_data
    c = 1
    while current_dissector and payload:
        payload, next_dissector_class = current_dissector.dissect(packet)
        if next_dissector_class:
            current_dissector = next_dissector_class()
        else:
            current_dissector = None
    return packet

# Paquete de ejemplo (Ethernet + IPv4 + TCP + HTTP)
raw_packet_4_tcp_http = (
    b'\x00\x0c\x29\x12\x34\x56\x00\x0c\x29\xab\xcd\xef\x08\x00'  # Ethernet
    b'\x45\x00\x00\x3c\x00\x00\x40\x00\x40\x06\x00\x00\xc0\xa8\x01\x01\x93\x18\xd8\x22'  # IPv4
    b'\xd4\x31\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00'  # TCP
    b'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'  # HTTP
)

# Paquete IPv6 + UDP + DNS
raw_packet_6_udp_dns = (
    b'\x00\x0c\x29\x12\x34\x56\x00\x0c\x29\xab\xcd\xef\x86\xdd'  # Ethernet (IPv6)
    b'\x60\x00\x00\x00\x00\x48\x11\xff\xfe\x80\x00\x00\x00\x00\x00\x00'  # IPv6
    b'\x02\x0c\x29\xff\xfe\xab\xcd\xef\x20\x01\x48\x60\x00\x00\x00\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x01'  # Direcciones IP
    b'\x02\x22\x00\x35\x00\x48\x00\x00'  # UDP (puerto 53)
    b'\x2e\xf0\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61'  # DNS
    b'\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01'
)


# Ethernet (IPv6) + IPv6 + TCP + HTTP
raw_packet_6_tcp_http = (
    # Ethernet (dest_mac, src_mac, ethertype=0x86DD)
    b'\x00\x0c\x29\x12\x34\x56\x00\x0c\x29\xab\xcd\xef\x86\xdd'
    # IPv6 (version=6, next_header=6=TCP)
    b'\x60\x00\x00\x00\x00\x24\x06\xff\x20\x01\x0d\xb8\x00\x00\x00\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8\x00\x00\x00\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x02'
    # TCP (src_port=54321, dst_port=80)
    b'\xd4\x31\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\xff\xff'
    b'\x00\x00\x00\x00'
    # HTTP
    b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
)



raw_packet = (
    # Ethernet (14 bytes)
    b'\x00\x0c\x29\x12\x34\x56'  # Destino MAC: 00:0c:29:12:34:56
    b'\x00\x0c\x29\xab\xcd\xef'  # Origen MAC: 00:0c:29:ab:cd:ef
    b'\x08\x00'                  # EtherType: 0x0800 (IPv4)

    # IPv4 (20 bytes)
    b'\x45\x00\x00\x54'          # Versión 4, IHL=5, Longitud total=84
    b'\x00\x00\x40\x00'          # ID=0, Flags=DF, Offset=0
    b'\x40\x06\x00\x00'          # TTL=64, Protocolo=6 (TCP), Checksum=0 (simplificado)
    b'\xc0\xa8\x01\x01'          # IP Origen: 192.168.1.1
    b'\x93\x18\xd8\x22'          # IP Destino: 147.24.216.34 (ejemplo.com)

    # TCP (20 bytes + opciones)
    b'\xd4\x31\x00\x50'          # Puerto Origen=54321, Destino=80 (HTTP)
    b'\x00\x00\x00\x00'          # Número de secuencia
    b'\x00\x00\x00\x00'          # Número de ACK
    b'\x50\x02\xff\xff'          # Longitud cabecera=20, Flags=SYN
    b'\x00\x00\x00\x00'          # Ventana=65535, Checksum=0 (simplificado)

    # HTTP (24 bytes)
    b'GET / HTTP/1.1\r\n'        # Petición HTTP
    b'Host: example.com\r\n\r\n'  # Cabecera Host + doble CRLF
)

# print("Paquete de Prueba (Ethernet + IPv4 + TCP + HTTP)")
# resultxd = analyze_packet(raw_packet)
# print(resultxd.layers)
# print("\n")
#
# print("Paquete (ETHERNET + IPv6 + UDP + DNS): ")
# result_6_udp_dns = analyze_packet(raw_packet_6_udp_dns)
# print("Capas identificadas:", result_6_udp_dns.layers)
# print("\n")
#
#
# print("Paquete (Ethernet + IPv4 + TCP + HTTP): ")
# result_4_tcp_http = analyze_packet(raw_packet_4_tcp_http)
# print("Capas identificadas:", result_4_tcp_http.layers)
# print("\n")
#
# print("Paquete (ETHERNET + IPv6 + TCP + HTTP): ")
# result_6_tcp_http = analyze_packet(raw_packet_6_tcp_http)
# print("Capas identificadas:", result_6_tcp_http.layers)
#
# print("####################################################################################################")

upload_pcap = st.file_uploader("El co;o de tu madre")
if upload_pcap is not None:
    try:
        # Guardar temporalmente el archivo cargado
        with open("temp.pcap", "wb") as f:
            f.write(upload_pcap.getbuffer())

        # Leer el PCAP con Scapy
        from scapy.all import rdpcap, IP_PROTOS
        packets = rdpcap("temp.pcap")
        candela = "temp.pcap"
        print(candela)
        # Mostrar información básica
        st.success(f"¡Archivo cargado! Número de paquetes: {len(packets)}")

        # Ejemplo: Mostrar resumen de los primeros 5 paquetes
        for pkt in packets[:5]:
            st.write(pkt.summary())

    except Exception as e:
        st.error(f"Error: {str(e)}")




