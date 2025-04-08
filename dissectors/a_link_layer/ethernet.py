from dissectors.dissector import Dissector
from operator import truediv
from utils.byte_ops import extract_mac, read_uint16_be
import binascii
import struct



class EthernetDissector(Dissector):
    def dissect(self, packet):
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


        return packet.get_payload(), next_dissector_type, next_dissector_id, layer_data







