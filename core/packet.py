

class Packet:
    def __init__(self, raw_data):
        self.raw_data = raw_data
        self.layers = {}
        self._current_offset = 0
        self.rawDataSize = len(raw_data)

    def getRawData(self,inicio, longitud):
        inicioParse = int(inicio)
        return self.raw_data[inicioParse:inicio+longitud]

    def getrawDataSize(self):
        entero = int(self.rawDataSize)
        return entero

    def add_layer(self, name, fields):
        self.layers[name] = fields

    def get_payload(self):
        return self.raw_data[self._current_offset:]
    
    def set_current_offset(self, offset):
        self._current_offset = offset
        
    def get_current_offset(self):
        return self._current_offset


    #El CRC es un metodo para verificar si la  subtrama perteneciente a la capa de enlace no esta corrupta o con datos perdidos
    #para este protocolo se usa la funcion de verificacion crc32 de la biblioteca binascii
