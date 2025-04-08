from dissectors.dissector import Dissector
from dissectors.registry import *
import struct
from utils import byte_ops

class UDPDissector(Dissector):
    def dissect(self, packet):
        info = packet.get_payload()
        src_port = byte_ops.read_uint16_be(info[0:2])
        dst_port = byte_ops.read_uint16_be(info[2:4])
        length = byte_ops.read_uint16_be(info[4:6])
        verificacion = verificarChecksumUdp(packet.getTempRawInfo(),info)
        layer_data = ('UDP', {
            'src_port': src_port,
            'dst_port': dst_port,
            'length': length
        })
        
        next_dissector_type =  'udp_port_types'
        next_dissector_id = dst_port
        
        packet.set_current_offset(packet.get_current_offset() + 8)
        
        return packet.get_payload(), next_dissector_type, next_dissector_id, layer_data

    def calculate_udp_checksum(self,ip_header, udp_header, udp_data):
        """Calcula el checksum UDP."""
        # Pseudo-header
        source_ip = ip_header[12:16]
        dest_ip = ip_header[16:20]
        reserved = 0
        #el protocolo 17 corresponde al udp
        protocol = 17
        udp_length = len(udp_header) + len(udp_data)

        pseudo_header = struct.pack('!4s4sBBH', source_ip, dest_ip, reserved, protocol, udp_length)
        checksum_data = pseudo_header + udp_header + udp_data

        # Padding si la longitud total es impar
        if len(checksum_data) % 2 != 0:
            checksum_data += b'\x00'

        checksum = 0
        for i in range(0, len(checksum_data), 2):
            word = (checksum_data[i] << 8) + checksum_data[i + 1]
            checksum += word
            checksum = (checksum & 0xffff) + (checksum >> 16)

        return ~checksum & 0xffff

    def verificarChecksumUdp(self,ip_header, udpInfo, received_checksum):
        """Verifica el checksum UDP recibido."""
        calculated_checksum = calculate_udp_checksum(ip_header, udp_header, udp_data)
        return calculated_checksum == received_checksum