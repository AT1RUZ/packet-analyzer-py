class Packet:
    def __init__(self, raw_data):
        self.raw_data = raw_data
        self.layers = {}
        self._current_offset = 0

    def add_layer(self, name, fields):
        self.layers[name] = fields

    def get_payload(self):
        return self.raw_data[self._current_offset:]
    
    def set_current_offset(self, offset):
        self._current_offset = offset
    def get_current_offset(self):
        return self._current_offset
        