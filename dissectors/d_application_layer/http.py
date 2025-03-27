from core.dissector import Dissector

class HTTPDissector(Dissector):
    def dissect(self, packet):
        try:
            http_data = packet.raw_data.decode('utf-8')
            if 'HTTP' in http_data:
                first_line = http_data.split('\r\n')[0]
                method, path, _ = first_line.split(' ')
                
                packet.add_layer('HTTP', {
                    'method': method,
                    'path': path
                })
        except UnicodeDecodeError:
            pass
        return None, None  # Fin de la cadena