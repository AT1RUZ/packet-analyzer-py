from dissectors.dissector import Dissector
from dissectors.registry import *
from dissectors.c_transport_layer.tcp import *
from dissectors.c_transport_layer.udp import *

class ARPDissector(Dissector):
    def dissect(self, packet):
        pass

# DissectorRegistry.register('ip_proto', 6, TCPDissector)
# DissectorRegistry.register('ip_proto', 17, UDPDissector)
