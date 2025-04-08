

class Packet:
    def __init__(self, raw_data):
        self.raw_data = raw_data
        self.dissected_layers = {}
        self._current_offset = 0
        self.rawDataSize = len(raw_data)
        self.tempRawInfo = []

    def getRawData(self,inicio, longitud):
        inicioParse = int(inicio)
        return self.raw_data[inicioParse:inicio+longitud]

    def getrawDataSize(self):
        entero = int(self.rawDataSize)
        return entero

    def add_layer(self, name, fields):
        self.dissected_layers[name] = fields

    def get_payload(self):
        return self.raw_data[self._current_offset:]
    
    def set_current_offset(self, offset):
        self._current_offset = offset
        
    def get_current_offset(self):
        return self._current_offset


    def getDissectedLayers(self):
        return self.dissected_layers

    def getTempRawInfo(self):
        return self.tempRawInfo

    def setTempRawInfo(self,info):
        self.tempRawInfo = info
