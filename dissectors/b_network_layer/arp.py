from dissectors.dissector import Dissector
from dissectors.registry import *


class ARPDissector(Dissector):
    def dissect(self, packet):
        pass

# DissectorRegistry.register('ip_proto', 6, TCPDissector)
# DissectorRegistry.register('ip_proto', 17, UDPDissector)
