from core.packet import Packet
from core.pcapReader import PcapReader
from core.PacketRegistry import PacketRegistry
from dissectors.registry import DissectorRegistry
from dissectors.dissector import Dissector
from export_to_JSON import export_to_JSON

class PacketAnalyzer:
    def __init__(self, file_path):
        """Inicializa el analizador y carga el archivo PCAP
        
        Args:
            file_path (str): Ruta al archivo PCAP a analizar
        """
        
        self.pcap = PcapReader(file_path)
        self.pcap_reader = self.pcap.abrir()
        self.dissector_registry = DissectorRegistry()
        self.packet_registry = PacketRegistry(file_path)
        self.analyzed_packets = 0
        self.pcaps_analyzed = 0
    
    def analyze_pcap_file(self):
        """Analiza el archivo PCAP cargado"""
        able_to_analyze = True
        while able_to_analyze:
            raw_packet = self.pcap_reader.leerSiguientePaquete()
            if not raw_packet:
                able_to_analyze = False
            else:
                packet = Packet(raw_packet)
                analyzed_packet = self.__analyze_packet(packet)
                self.packet_registry.add_dissected_packet(analyzed_packet)
                self.analyzed_packets += 1
        self.pcaps_analyzed += 1
        return True

    def __analyze_packet(self, packet: Packet):
        """Analiza un paquete individual"""
       
        current_dissector = self.dissector_registry.get_dissector('link_layer_types','eth')
        payload = packet.raw_data
        analyzed_layers = 0
       
        while current_dissector and payload :
            # analyzed_layers += 1
            # print(analyzed_layers)
            payload, next_dissector_type, next_dissector_id, layer_data = current_dissector.dissect(packet)
            if layer_data:
                packet.add_layer(layer_data[0], layer_data[1])
            if next_dissector_type and next_dissector_id:
                current_dissector = self.dissector_registry.get_dissector(next_dissector_type, next_dissector_id)
            else:
                current_dissector = None
        return packet
        
    
    # def print_pcap_packet_info(self):
    #     """Imprime la información de los paquetes PCAP analizados"""
    #     try:
    #         if self.analyze_pcap_file():
    #             self.__pcap_analyzer.print_packet_info()
    #         else:
    #             print("Error: No se pudo analizar el archivo PCAP")
    #     except ValueError as error:
    #         if not self.__pcap_analyzer.is_pcap_header_decoded:
    #             print("Error: No hay datos suficientes para analizar el paquete")
    #         elif self.__pcap_analyzer.decoded_protocols == 0:
    #             print("Error: El primer paquete está dañado")
    #         else:
    #             print(f"Error: {str(error)}")
    #
    # def write_pcap_packet_info(self, output_file):
    #     """Escribe la información de los paquetes PCAP analizados en un archivo
    #
    #     Args:
    #         output_file (str): Ruta del archivo donde se escribirá la información
    #     """
    #     try:
    #         if self.analyze_pcap_file():
    #             with open(output_file, 'w') as f:
    #                 # Escribir información del encabezado PCAP
    #                 f.write("=== Información del archivo PCAP ===\n")
    #                 for key, value in self.__pcap_analyzer.get_pcap_header_info().items():
    #                     f.write(f"{key}: {value}\n")
    #                 f.write("\n")
    #
    #                 # Escribir información de cada paquete
    #                 for i in range(self.__pcap_analyzer.decoded_protocols):
    #                     packet_key = f"packet_{i}"
    #
    #                     f.write(f"\n=== Paquete {i} ===\n")
    #
    #                     # Escribir información del encabezado
    #                     headers_info = self.__pcap_analyzer.get_packets_headers_info()
    #                     if packet_key in headers_info:
    #                         f.write("Header Info:\n")
    #                         for key, value in headers_info[packet_key].items():
    #                             f.write(f"  {key}: {value}\n")
    #
    #                     # Escribir información de protocolos
    #                     protocols_info = self.__pcap_analyzer.get_packets_protocols_info()
    #                     if packet_key in protocols_info and protocols_info[packet_key]:
    #                         f.write("Protocol Info:\n")
    #                         for protocol, fields in protocols_info[packet_key].items():
    #                             f.write(f"  {protocol}:\n")
    #                             for key, value in fields.items():
    #                                 f.write(f"    {key}: {value}\n")
    #                     f.write("\n")
    #             print(f"Información escrita en {output_file}")
    #         else:
    #             print("Error: No se pudo analizar el archivo PCAP")
    #     except ValueError as error:
    #         if not self.__pcap_analyzer.get_pcap_header_decoded():
    #             print("Error: No hay datos suficientes para analizar el paquete")
    #         elif self.__pcap_analyzer.get_decoded_protocols() == 0:
    #             print("Error: El primer paquete está dañado")
    #         else:
    #             print(f"Error: {str(error)}")

    def guardarJSON(self):
        exportador = export_to_JSON()
        datos = self.packet_registry.get_dissected_packets()
        exportador.escribirJson(datos)



