from dissectors.dissectors_list import get_dissectors_list

class DissectorRegistry:
    def __init__(self):
        self._registry = {
            'link_layer_types': {},
            'ether_type': {},
            'ip_proto_types': {},
            'tcp_port_types': {},
            'udp_port_types': {}
        }
        self.register_all_dissectors()
        

    
    def register(self, protocol_type, identifier, dissector):
        self._registry[protocol_type][identifier] = dissector
        
    
    
    def get_dissector(self, protocol_type, identifier):
        return self._registry[protocol_type].get(identifier)
    
    
    def get_registry(self):
        return self._registry

    def register_all_dissectors(self):
        dissectors_list = get_dissectors_list()
        for dissector_info in dissectors_list:
            protocol_type = dissector_info[0]
            identifier = dissector_info[1]
            dissector = dissector_info[2]
            self.register(protocol_type, identifier, dissector)

    