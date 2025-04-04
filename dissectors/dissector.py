from abc import ABC, abstractmethod
from dissectors.registry import *

class Dissector(ABC):
    @abstractmethod
    def dissect(self, packet):
        pass
    