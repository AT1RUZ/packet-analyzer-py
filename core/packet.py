class Packet:
    def __init__(self, raw_data):
        self.raw_data = raw_data
        self.layers = {}
        self._current_offset = 0

    def add_layer(self, name, fields):
        self.layers[name] = fields

    def get_payload(self, offset):
        return self.raw_data[offset:]
        