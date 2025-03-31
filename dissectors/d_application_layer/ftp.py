from core.dissector import Dissector
from core.registry import *
from core.registry import *
from utils.byte_ops import read_ascii_string, read_ascii_until_space

class FTPDissector(Dissector):
    # Códigos de respuesta FTP comunes
    FTP_CODES = {
        '110': 'Restart marker reply',
        '120': 'Service ready in nnn minutes',
        '125': 'Data connection already open; transfer starting',
        '150': 'File status okay; about to open data connection',
        '200': 'Command okay',
        '220': 'Service ready for new user',
        '226': 'Closing data connection',
        '230': 'User logged in, proceed',
        '331': 'User name okay, need password',
        '425': 'Can\'t open data connection',
        '500': 'Syntax error, command unrecognized',
        '530': 'Not logged in'
    }

    def dissect(self, packet):
        payload = packet.get_payload()
        if not payload:
            return None, None

        # Intentar decodificar como ASCII
        ftp_data = read_ascii_string(payload)
        if not ftp_data:
            # Si no es ASCII, son datos binarios
            packet.add_layer('FTP', {
                'type': 'data',
                'length': len(payload)
            })
            return None, None

        # Es un mensaje ASCII, procesar comando o respuesta
        if ftp_data.startswith('USER'):
            command, argument = read_ascii_until_space(payload)
            packet.add_layer('FTP', {
                'command': command,
                'argument': argument,
                'type': 'request'
            })
        elif ftp_data.startswith('PASS'):
            command, _ = read_ascii_until_space(payload)
            packet.add_layer('FTP', {
                'command': command,
                'argument': '*****',  # Por seguridad
                'type': 'request'
            })
        elif ftp_data[:3].isdigit():
            # Es una respuesta del servidor
            code = ftp_data[:3]
            packet.add_layer('FTP', {
                'code': code,
                'message': self.FTP_CODES.get(code, 'Unknown response'),
                'full_response': ftp_data[4:],
                'type': 'response'
            })
        else:
            # Otros comandos FTP
            command, argument = read_ascii_until_space(payload)
            if command:
                packet.add_layer('FTP', {
                    'command': command,
                    'argument': argument if argument else '',
                    'type': 'request'
                })

        return None, None

# Registrar el disector para los puertos FTP
DissectorRegistry.register('tcp_port', 21, FTPDissector)  # Puerto de control FTP
DissectorRegistry.register('tcp_port', 20, FTPDissector)  # Puerto de datos FTP 