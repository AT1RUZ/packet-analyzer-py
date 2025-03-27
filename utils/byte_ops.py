def extract_mac(data):
    """Convierte 6 bytes en una dirección MAC formato xx:xx:xx:xx:xx:xx"""
    return ":".join(f"{byte:02x}" for byte in data)

def read_uint8(data):
    """Lee 1 byte como entero sin signo"""
    if isinstance(data, bytes):
        return data[0]
    elif isinstance(data, int):
        return data
    else:
        raise TypeError("data debe ser bytes o int")

def read_uint16_be(data):
    """Lee 2 bytes big-endian como entero sin signo"""
    return int.from_bytes(data, byteorder='big')

def read_uint32_be(data):
    """Lee 4 bytes big-endian como entero sin signo"""
    return int.from_bytes(data, byteorder='big')

def read_ipv6_address(data):
    """Convierte 16 bytes en dirección IPv6"""
    return ":".join(f"{(data[i]<<8)+data[i+1]:04x}" for i in range(0, 16, 2))

def read_dns_name(data, offset):
    """Lee nombres DNS con compresión de punteros"""
    name = []
    while True:
        length = data[offset]
        if length == 0:
            break
        if (length & 0xC0) == 0xC0:  # Puntero comprimido
            ptr = ((length & 0x3F) << 8) + data[offset+1]
            name.append(read_dns_name(data, ptr)[0])
            offset += 1
            break
        offset += 1
        name.append(data[offset:offset+length].decode())
        offset += length
    return ".".join(name), offset + 1