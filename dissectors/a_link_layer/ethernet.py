from operator import truediv

from dissectors.dissector import Dissector
from dissectors.b_network_layer.ipv4 import *
from dissectors.b_network_layer.ipv6 import *
from dissectors.b_network_layer.arp import *
from dissectors.registry import *
from utils.byte_ops import extract_mac, read_uint16_be
import binascii
import struct

class EthernetDissector(Dissector):
    def dissect(self, packet):
        fullPacket = packet
        header = packet.get_payload()
        dest_mac = extract_mac(header[0:6])
        src_mac = extract_mac(header[6:12])
        ethertype = read_uint16_be(header[12:14])


        packet.add_layer('Ethernet', {
            'dest_mac': dest_mac,
            'src_mac': src_mac,
            'ethertype': f"0x{ethertype:04x}"
        })
        
        next_dissector = DissectorRegistry.get_dissector('ethertype', ethertype)
        packet.set_current_offset(14)

        if EthernetDissector.verificar_crc32_ethernet():
            return packet.get_payload(), next_dissector
        else:
            return None

        # El CRC es un metodo para verificar si la  subtrama perteneciente a la capa de enlace no esta corrupta o con datos perdidos
        # para este protocolo se usa la funcion de verificacion crc32 de la biblioteca binascii
        # La funcion debe recibir el puntero  y la informacion cruda del paquete

    def verificar_crc32_ethernet(self,packet):
        calculated_crc = binascii.crc32(
            packet.raw_data[
            :packet.raw_data - 4]) & 0xFFFFFFFF  # Calcula crc sobre el fragmento sin los últimos 4 bytes (FCS)
        received_crc = struct.unpack('<I', packet.raw_data[- 4:])[
            0]  # Lee los últimos 4 bytes como el crc recibido
        return calculated_crc == received_crc



# DissectorRegistry.register('ethertype', 0x0800, IPv4Dissector)
# DissectorRegistry.register('ethertype', 0x86DD, IPv6Dissector)
# DissectorRegistry.register('ethertype', 0x0806, ARPDissector)


