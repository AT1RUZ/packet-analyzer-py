from collections import deque
import pcapReader

class PacketRegistry:
    def __init__(self, archivoPcap):
        self.pcapReader = pcapReader.PcapReader(archivoPcap)
        self.packetQueue = deque()

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
