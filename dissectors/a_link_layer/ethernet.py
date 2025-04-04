from operator import truediv

from dissectors.dissector import Dissector

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


        layer_data =("Ethernet", {
            'dest_mac': dest_mac,
            'src_mac': src_mac,
            'ethertype': f"0x{ethertype:04x}"
        })
        
        next_dissector_type =  'ether_types'
        next_dissector_id = ethertype
        packet.set_current_offset(14)

        # if self.verificar_crc32_ethernet(packet):
        return packet.get_payload(), next_dissector_type, next_dissector_id, layer_data
        # else:
        #     return None

        # El CRC es un metodo para verificar si la  subtrama perteneciente a la capa de enlace no esta corrupta o con datos perdidos
        # para este protocolo se usa la funcion de verificacion crc32 de la biblioteca binascii
        # La funcion debe recibir el puntero  y la informacion cruda del paquete

    def verificar_crc32_ethernet(self, packet):
        calculated_crc = binascii.crc32(
            packet.raw_data[
            :packet.raw_data - 4]) & 0xFFFFFFFF  # Calcula crc sobre el fragmento sin los últimos 4 bytes (FCS)
        received_crc = struct.unpack('<I', packet.raw_data[- 4:])[
            0]  # Lee los últimos 4 bytes como el crc recibido
        return calculated_crc == received_crc





