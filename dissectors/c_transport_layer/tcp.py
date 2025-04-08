from dissectors.dissector import Dissector
from dissectors.registry import *
import struct
from utils.byte_ops import read_uint16_be, read_uint8

class TCPDissector(Dissector):
    def dissect(self, packet):
        payload = packet.get_payload()

        src_port = read_uint16_be(payload[0:2])
        dst_port = read_uint16_be(payload[2:4])
        
        header_length = ((payload[12] >> 4) & 0x0F) * 4
        checksumRecibido = (payload[16] << 8) + payload[17]
        checksumCalculado = self.calcularChecksumTCP(packet.getTempRawInfo(),payload,header_length)
        # if checksumcalculado == checksumRecibido:
        #     print("en talla")
        if header_length < 20:
            raise ValueError(f"TCP header length inválido: {header_length} bytes")
        
        layer_data = ('TCP', {
            'src_port': src_port,
            'dst_port': dst_port,
            'header_length': header_length
        })
        
        next_dissector_type =  'tcp_port_types'
        next_dissector_id = dst_port
        
        # Actualizar el offset basado en el header length real
        packet.set_current_offset(packet.get_current_offset() + header_length)
        
        return packet.get_payload(), next_dissector_type, next_dissector_id, layer_data

    def calcularChecksumTCP(self, ip_header, tcp_header_plus_data, tcpHeaderLength):
        """Calcula el checksum TCP con la pseudo-cabecera IPv4."""

        ipSrc = ip_header[12:16]
        ipDst = ip_header[16:20]
        # Crear la pseudo-cabecera IPv4
        pseudoCabecera = self.crearPseudoHeader(ipSrc,ipDst,tcpHeaderLength)
        temp = bytearray(tcp_header_plus_data)
        temp[16:18] = b'\x00\x00'
        tcp_header_plus_data = bytes(temp)

        # Concatenar la pseudo-cabecera y los datos TCP
        checksum_data = pseudoCabecera + tcp_header_plus_data

        # Asegurar una longitud par para el cálculo del checksum
        if len(checksum_data) % 2 != 0:
            checksum_data += b'\x00'

        checksum = 0
        # for i in range(0, len(checksum_data), 2):
        #     word = (checksum_data[i] << 8) + checksum_data[i + 1]
        #     checksum += word
        #     checksum &= 0xFFFF
        #
        # # Sumar los acarreos
        # while (checksum >> 16) > 0:
        #     checksum = (checksum & 0xFFFF) + (checksum >> 16)
        #
        # # Tomar el complemento a uno
        # checksum = ~checksum & 0xFFFF
        for i in range(0, len(checksum_data), 2):
            if i + 1 < len(checksum_data):
                word = (checksum_data[i] << 8) + checksum_data[i + 1]
            else:
                word = (checksum_data[i] << 8)
            checksum += word

        # Manejar el acarreo
        while (checksum >> 16) > 0:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        # One's complement
        checksum = ~checksum & 0xFFFF
        return checksum

    def crearPseudoHeader(self,srcIp, dstIp, tcp_length):
        """
        Crea la pseudo-cabecera TCP manualmente y la devuelve como una secuencia de bytes.
        """
        reserved_byte = b'\x00'
        # 4. Protocolo (1 byte) - TCP es 6
        protocol_byte = b'\x06'
        # 5. Longitud Total TCP (2 bytes - big-endian)
        tcp_length_bytes = bytes(tcp_length)

        # Concatenar todos los campos
        pseudo_header = srcIp+ dstIp +protocol_byte +  reserved_byte + tcp_length_bytes

        return pseudo_header