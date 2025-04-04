from core.packet_analyzer import PacketAnalyzer
from core.PacketRegistry import PacketRegistry
import time

# p1 = PacketAnalyzer("twotomany.pcap")
# inicio = time.time()
# p1.analyze_pcap_file()
# fin = time.time()
# print(f"Tiempo total: {fin - inicio} segundos el algoritmo solo")

# p2 = PacketAnalyzer("twotomany.pcap")
# inicio = time.time()
# p2.print_pcap_packet_info()
# fin = time.time()
# print(f"Tiempo total: {fin - inicio} segundos en ejecutar algoritmo e imprimir en pantalla")

# p3 = PacketAnalyzer("Noobs Keylogger.pcap")
# inicio = time.time()
# p3.write_pcap_packet_info("prueba.txt")
# fin = time.time()
# print(f"Tiempo total: {fin - inicio} segundos en ejecutar algoritmo e escribir en txt")


inicio = time.time()
packets = 0
for i  in range(10):
    p = PacketAnalyzer("Noobs Keylogger.pcap")
    p.analyze_pcap_file()
    p.guardarJSON()
    packets += p.analyzed_packets
fin = time.time()

print(f"Paquetes analizados: {packets} \nArchivos .pcap analizados: {i+1} \nTiempo: {fin - inicio} segundos el algoritmo solo")

