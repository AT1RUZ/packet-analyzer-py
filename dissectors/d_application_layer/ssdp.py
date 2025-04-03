from dissectors.dissector import Dissector
from dissectors.registry import *
from utils.byte_ops import read_http_headers

class SSDPDissector(Dissector):
    # Métodos SSDP comunes
    SSDP_METHODS = {
        'NOTIFY': 'Notification of service availability',
        'M-SEARCH': 'Search for devices/services',
        'HTTP/1.1': 'SSDP Response'
    }

    def dissect(self, packet):
        payload = packet.get_payload()
        if not payload:
            return None, None

        start_line, headers = read_http_headers(payload)
        if not start_line:
            return None, None

        # Determinar tipo de mensaje SSDP
        parts = start_line.split(' ')
        if parts[0] in ['NOTIFY', 'M-SEARCH']:
            # Es una solicitud
            packet.add_layer('SSDP', {
                'type': 'request',
                'method': parts[0],
                'description': self.SSDP_METHODS.get(parts[0], 'Unknown method'),
                'target': parts[1],
                'version': parts[2],
                'headers': {
                    'HOST': headers.get('HOST', ''),
                    'NT': headers.get('NT', ''),  # Notification Type
                    'NTS': headers.get('NTS', ''),  # Notification Sub Type
                    'USN': headers.get('USN', ''),  # Unique Service Name
                    'LOCATION': headers.get('LOCATION', ''),
                    'CACHE-CONTROL': headers.get('CACHE-CONTROL', ''),
                    'MAN': headers.get('MAN', ''),  # Mandatory extension
                    'MX': headers.get('MX', ''),  # Maximum wait time
                    'ST': headers.get('ST', '')   # Search Target
                }
            })
        else:
            # Es una respuesta
            packet.add_layer('SSDP', {
                'type': 'response',
                'version': parts[0],
                'status_code': parts[1],
                'status_text': ' '.join(parts[2:]),
                'headers': {
                    'LOCATION': headers.get('LOCATION', ''),
                    'USN': headers.get('USN', ''),
                    'CACHE-CONTROL': headers.get('CACHE-CONTROL', ''),
                    'SERVER': headers.get('SERVER', ''),
                    'ST': headers.get('ST', ''),
                    'EXT': headers.get('EXT', '')
                }
            })

        return None, None

# Registrar el disector para SSDP (UDP puerto 1900)
# DissectorRegistry.register('udp_port', 1900, SSDPDissector) 