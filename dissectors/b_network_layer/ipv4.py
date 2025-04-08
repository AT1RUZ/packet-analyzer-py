from dissectors.dissector import Dissector
from dissectors.registry import *
from utils.byte_ops import read_uint8, read_uint16_be

class IPv4Dissector(Dissector):
    def dissect(self, packet):
        payload = packet.get_payload()
        
        ihl = (payload[0] & 0x0F) * 4
        
        if ihl < 20 or ihl > 60:
            raise ValueError(f"IHL inválido: {ihl} bytes")

        #Fragmento para verificar el correcto valor de suma de chequeo del paquete
        ipv4Header = payload[:ihl]
        checksumRecibido = (payload[10] << 8) + payload[11]
        headerSinChecksum = bytearray(ipv4Header)
        headerSinChecksum[10:12] = b'\x00\x00'

        checksumCorrecto = self.calcularSuma_ipv4(bytes(headerSinChecksum)) == checksumRecibido
        if checksumCorrecto:
            print("en talla")
        protocol = read_uint8(payload[9])
        layer_data = ('IPv4', {
            'src_ip': '.'.join(map(str, payload[12:16])),
            'dst_ip': '.'.join(map(str, payload[16:20])),
            'protocol': protocol,
            'header_length': ihl,
            'Checksum valido':checksumCorrecto
        })
        
        next_dissector_type =  'ip_proto_types'
        next_dissector_id = protocol
        
        # Actualizar el offset para el siguiente protocolo
        packet.set_current_offset(packet.get_current_offset() + ihl)
        
        return packet.get_payload(), next_dissector_type, next_dissector_id, layer_data

    def calcularSuma_ipv4(self,header):
        """Calculates the IPv4 header checksum."""
        checksum = 0
        # Iterate through 16-bit words in the header
        for i in range(0, len(header), 2):
            if i + 1 < len(header):
                word = (header[i] << 8) + header[i + 1]
            else:
                word = (header[i] << 8)
            checksum += word

        # Handle overflow
        while (checksum >> 16) > 0:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        # One's complement
        checksum = ~checksum & 0xFFFF
        return checksum