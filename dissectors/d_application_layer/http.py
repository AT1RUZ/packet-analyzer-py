from dissectors.dissector import Dissector
from collections import defaultdict

class HTTPDissector(Dissector):
    def dissect(self, packet):
        try:
            coded_info = packet.get_payload()
            # Decodificar como UTF-8 (o Latin-1 como fallback)
            try:
                http_data = coded_info.decode('utf-8')
            except UnicodeDecodeError:
                http_data = coded_info.decode('latin-1')

            if not ('HTTP/' in http_data or any(method in http_data for method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD'])):
                return None, None  # No es HTTP

            # Parsear línea de inicio (request/response)
            lines = http_data.split('\r\n')
            start_line = lines[0]
            
            http_info = {
                'headers': defaultdict(str),
                'body': None
            }

            # Determinar si es request o response
            if start_line.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS')):
                # HTTP Request
                method, path, version = start_line.split(' ', 2)
                http_info.update({
                    'type': 'request',
                    'method': method,
                    'path': path,
                    'version': version
                })
            elif 'HTTP/' in start_line:
                # HTTP Response
                version, status_code, *status_msg = start_line.split(' ', 2)
                http_info.update({
                    'type': 'response',
                    'version': version,
                    'status_code': status_code,
                    'status_message': status_msg[0] if status_msg else ''
                })

            # Parsear headers
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if not line.strip():  # Línea vacía indica fin de headers
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    http_info['headers'][key.strip()] = value.strip()

            # Capturar body si existe
            if body_start < len(lines):
                http_info['body'] = '\r\n'.join(lines[body_start:])

            packet.add_layer('HTTP', http_info)

        except Exception as e:
            packet.add_layer('HTTP', {
                'error': f'HTTP parsing failed: {str(e)}',
                'raw': packet.raw_data[:100].hex()  # Muestra primeros 100 bytes en hex
            })

        return None, None, None, None  # Fin de la cadena