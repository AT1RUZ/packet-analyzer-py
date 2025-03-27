class DissectorRegistry:
    _registry = {
        'ethertype': {},
        'ip_proto': {},
        'tcp_port': {},
        'udp_port': {}
    }

    @classmethod
    def register(cls, protocol_type, identifier, dissector):
        cls._registry[protocol_type][identifier] = dissector
        
    
    @classmethod
    def get_dissector(cls, protocol_type, identifier):
        return cls._registry[protocol_type].get(identifier)
    