class PcapPacket:
    def __init__(self, raw_data):
        self.raw_data = raw_data
        self._current_offset = 24
        self.decoded_protocols = 0
        
        # Atributos del encabezado PCAP
        self.magic_number = None
        self.version_major = None
        self.version_minor = None
        self.thiszone = None
        self.sigfigs = None
        self.snaplen = None
        self.network = None
        self.is_pcap_header_decoded = False
        
        # Atributos del encabezado de paquete
        self.packet_timestamp_seconds = None
        self.packet_timestamp_microseconds = None
        self.packet_captured_length = None
        self.packet_original_length = None
        self.is_packet_header_decoded = False
        
        # Inicializar información
        self.pcap_header_info = self.__get_pcap_info()
        self.packets_protocols_info = {}
        self.packets_headers_info = {}

    # Getters
    def get_pcap_header_decoded(self):
        return self.is_pcap_header_decoded
    
    def get_decoded_protocols(self):
        return self.decoded_protocols
    
    def get_current_offset(self):
        """Obtiene el offset actual"""
        return self._current_offset
        
    def get_analyzed_packet_amount(self):
        """Obtiene la cantidad de paquetes analizados"""
        return len(self.protocols_packets_info)
    
    def get_pcap_header_info(self):
        """Obtiene la información del encabezado PCAP"""
        return self.pcap_header_info
    
    def get_packets_protocols_info(self):
        return self.packets_protocols_info
    
    def get_packets_headers_info(self):
        return self.packets_headers_info    
    
    def get_packet_data(self):
        """Retorna los datos del paquete basado en la longitud capturada"""
        if not self.is_packet_header_decoded:
            self.__decode_packet_header()
        return self.raw_data[self._current_offset+16:self._current_offset+16+self.packet_captured_length]
    
    def get_next_packet(self):
        """Obtiene el siguiente paquete del archivo PCAP"""
        packet_header_info = self.__get_packet_info()
        if not packet_header_info:
            return None
        self.add_packet_header_info(packet_header_info)
        packet_start = self.get_current_offset()
        self.set_current_offset(self.get_current_offset() + self.packet_captured_length)
        packet_end = self.get_current_offset()
        packet = self.raw_data[packet_start:packet_end]
        self.is_packet_header_decoded = False
        if packet_end == packet_start:
            return None
        return packet

    # Setters
    def set_current_offset(self, offset):
        """Establece el offset actual"""
        self._current_offset = offset

    # Add methods
    def add_packet_protocols_info(self, protocols_info):
        """Añade información de protocolos de un paquete"""
        if protocols_info:
            self.packets_protocols_info[f"packet_{self.decoded_protocols}"] = protocols_info.layers
        
    def add_packet_header_info(self, header_protocol_info):
        """Añade información del encabezado de un paquete"""
        self.packets_headers_info[f"packet_{self.decoded_protocols}"] = header_protocol_info

    # Validation methods
    def is_valid_pcap(self):
        """Verifica si el número mágico es válido"""
        valid_magic_numbers = [0xa1b2c3d4, 0xd4c3b2a1]
        return self.magic_number in valid_magic_numbers

    # Private methods for decoding
    def __decode_pcap_header(self):
        """Decodifica el encabezado global del archivo PCAP"""
        if len(self.raw_data) < 24:
            return None
            
            
        # Decodificar cada campo
        self.magic_number = int.from_bytes(self.raw_data[0:4], byteorder='little')
        self.version_major = int.from_bytes(self.raw_data[4:6], byteorder='little')
        self.version_minor = int.from_bytes(self.raw_data[6:8], byteorder='little')
        self.thiszone = int.from_bytes(self.raw_data[8:12], byteorder='little')
        self.sigfigs = int.from_bytes(self.raw_data[12:16], byteorder='little')
        self.snaplen = int.from_bytes(self.raw_data[16:20], byteorder='little')
        self.network = int.from_bytes(self.raw_data[20:24], byteorder='little')
        self.is_pcap_header_decoded = True
        return True
        
    def __decode_packet_header(self):
        """Decodifica el encabezado de un paquete individual"""
        if len(self.raw_data[self._current_offset:]) < 16:
            return None
            raise ValueError("Datos insuficientes para un encabezado de paquete")
            
        # Decodificar cada campo
        self.packet_timestamp_seconds = int.from_bytes(self.raw_data[self._current_offset:self._current_offset+4], byteorder='little')
        self.packet_timestamp_microseconds = int.from_bytes(self.raw_data[self._current_offset+4:self._current_offset+8], byteorder='little')
        self.packet_captured_length = int.from_bytes(self.raw_data[self._current_offset+8:self._current_offset+12], byteorder='little')
        self.packet_original_length = int.from_bytes(self.raw_data[self._current_offset+12:self._current_offset+16], byteorder='little')
        self.is_packet_header_decoded = True
        self.set_current_offset(self.get_current_offset()+16)
        self.decoded_protocols += 1
        
        
    def __get_pcap_info(self):
        """Retorna un diccionario con la información del encabezado PCAP"""
        if not self.is_pcap_header_decoded:
            if not self.__decode_pcap_header():
                return None
            
        return {
            'magic_number': hex(self.magic_number),
            'version': f"{self.version_major}.{self.version_minor}",
            'timezone': self.thiszone,
            'timestamp_precision': self.sigfigs,
            'snapshot_length': self.snaplen,
            'link_layer_type': self.network
        }
    
    def __get_packet_info(self):
        """Retorna un diccionario con la información del encabezado del paquete"""
        if not self.is_packet_header_decoded:
            self.__decode_packet_header()
        return {
            'timestamp': f"{self.packet_timestamp_seconds}.{self.packet_timestamp_microseconds}",
            'packet_captured_length': self.packet_captured_length,
            'packet_original_length': self.packet_original_length
        }
    
    #Info output
    def print_packet_info(self):
        for i in range(self.decoded_protocols):
            packet_key = f"packet_{i}"
            
            print(f"\n=== Paquete {i} ===")
            
            # Imprimir información del encabezado
            if packet_key in self.packets_headers_info:
                print("Header Info:")
                for key, value in self.packets_headers_info[packet_key].items():
                    print(f"  {key}: {value}")
            
            # Imprimir información de protocolos
            if packet_key in self.packets_protocols_info:
                print("Protocol Info:")
                for key, value in self.packets_protocols_info[packet_key].items():
                    print(f"  {key}: {value}")