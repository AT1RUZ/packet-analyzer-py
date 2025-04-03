from abc import ABC, abstractmethod
from dissectors.registry import *

class Dissector(ABC):
    @abstractmethod
    def dissect(self, packet):
        pass
    
    @classmethod
    def register(cls, protocol_type, identifier, dissector):
        DissectorRegistry.register(protocol_type, identifier, dissector)