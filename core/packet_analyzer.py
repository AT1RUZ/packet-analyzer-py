from core.packet import Packet
from core.registry import *
from core.pcap_analyzer import PcapPacket
from dissectors.a_link_layer.ethernet import EthernetDissector

class PacketAnalyzer:
    def __init__(self, file_path):
        """Inicializa el analizador y carga el archivo PCAP
        
        Args:
            file_path (str): Ruta al archivo PCAP a analizar
        
        Raises:
            FileNotFoundError: Si no se encuentra el archivo
            Exception: Si hay un error al cargar el archivo
        """
        
        
        try:
            with open(file_path, "rb") as p:
                raw_pcap_file = p.read()
                self.__pcap_analyzer = PcapPacket(raw_pcap_file)
        except FileNotFoundError:
            print(f"Error: No se pudo encontrar el archivo {file_path}")
            raise
        except Exception as e:
            print(f"Error al cargar el archivo: {str(e)}")
            raise

    def analyze_pcap_file(self):
        """Analiza el archivo PCAP cargado"""
        able_to_analyze = True
        while able_to_analyze:
            raw_packet = self.__pcap_analyzer.get_next_packet()
            if not raw_packet:
                able_to_analyze = False
            else:
                analyzed_packet = self.__analyze_packet(raw_packet)
                self.__pcap_analyzer.add_packet_protocols_info(analyzed_packet)
        return True

    def __analyze_packet(self, raw_data):
        """Analiza un paquete individual"""
        if len(raw_data) != 0:
            packet = Packet(raw_data)
            current_dissector = EthernetDissector()
            payload = raw_data
            
            while current_dissector and payload:
                payload, next_dissector_class = current_dissector.dissect(packet)
                if next_dissector_class:
                    current_dissector = next_dissector_class()
                else:
                    current_dissector = None
            return packet
        return None
    
    def print_pcap_packet_info(self):
        """Imprime la información de los paquetes PCAP analizados"""
        try:
            if self.analyze_pcap_file():
                self.__pcap_analyzer.print_packet_info()
            else:
                print("Error: No se pudo analizar el archivo PCAP")
        except ValueError as error:
            if not self.__pcap_analyzer.is_pcap_header_decoded:
                print("Error: No hay datos suficientes para analizar el paquete")
            elif self.__pcap_analyzer.decoded_protocols == 0:
                print("Error: El primer paquete está dañado")
            else:
                print(f"Error: {str(error)}")

    def write_pcap_packet_info(self, output_file):
        """Escribe la información de los paquetes PCAP analizados en un archivo
        
        Args:
            output_file (str): Ruta del archivo donde se escribirá la información
        """
        try:
            if self.analyze_pcap_file():
                with open(output_file, 'w') as f:
                    # Escribir información del encabezado PCAP
                    f.write("=== Información del archivo PCAP ===\n")
                    for key, value in self.__pcap_analyzer.get_pcap_header_info().items():
                        f.write(f"{key}: {value}\n")
                    f.write("\n")
                    
                    # Escribir información de cada paquete
                    for i in range(self.__pcap_analyzer.decoded_protocols):
                        packet_key = f"packet_{i}"
                        
                        f.write(f"\n=== Paquete {i} ===\n")
                        
                        # Escribir información del encabezado
                        headers_info = self.__pcap_analyzer.get_packets_headers_info()
                        if packet_key in headers_info:
                            f.write("Header Info:\n")
                            for key, value in headers_info[packet_key].items():
                                f.write(f"  {key}: {value}\n")
                        
                        # Escribir información de protocolos
                        protocols_info = self.__pcap_analyzer.get_packets_protocols_info()
                        if packet_key in protocols_info and protocols_info[packet_key]:
                            f.write("Protocol Info:\n")
                            for protocol, fields in protocols_info[packet_key].items():
                                f.write(f"  {protocol}:\n")
                                for key, value in fields.items():
                                    f.write(f"    {key}: {value}\n")
                        f.write("\n")
                print(f"Información escrita en {output_file}")
            else:
                print("Error: No se pudo analizar el archivo PCAP")
        except ValueError as error:
            if not self.__pcap_analyzer.get_pcap_header_decoded():
                print("Error: No hay datos suficientes para analizar el paquete")
            elif self.__pcap_analyzer.get_decoded_protocols() == 0:
                print("Error: El primer paquete está dañado")
            else:
                print(f"Error: {str(error)}")
                