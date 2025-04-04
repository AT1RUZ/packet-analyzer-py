from collections import deque
from core.packet import Packet
from core.pcapReader import PcapReader

class PacketRegistry:
    def __init__(self, archivoPcap):
        self.pcapReader = PcapReader(archivoPcap)
        self.packetQueue = deque()
        self.dissected_packets = []
        
    def get_dissected_packets(self):
        if len(self.dissected_packets) > 0:
            return None
        return self.dissected_packets

    def add_dissected_packet(self, packet: Packet ):
        self.dissected_packets.append(packet)

    
    def procesarPaquetes(self):
        try:
            self.pcapReader.abrir()
            for _ in range(3):
                packet = self.pcapReader.leerSiguientePaquete()
                if packet:
                    self.packetQueue.append(packet)
        finally:
            self.pcapReader.cerrar()

    def obtenerCola(self):
        return self.packetQueue
