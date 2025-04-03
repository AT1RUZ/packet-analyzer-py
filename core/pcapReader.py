import struct

class PcapReader:
    def __init__(self, ruta_Archivo):
        self.rutaArchivo = ruta_Archivo
        self.archivo = None
        self.ordenBytes = None
        self.indiceActual = 0  # Índice del próximo paquete a leer (comienza en 0)
        self.posicionArchivo = 24  # Inicializar después de la cabecera del archivo pcap

    def abrir(self):
        try:
            if self.archivo is None:
                self.archivo = open(self.rutaArchivo, 'rb')
                self.archivo.seek(self.posicionArchivo)
                if self.ordenBytes is None:
                    cabeceraGlobal = self.archivo.read(24)
                    if len(cabeceraGlobal) < 24:
                        raise ValueError("Archivo pcap incompleto o inválido (cabecera global).")
                    numeroMagico = struct.unpack("<I", cabeceraGlobal[:4])[0]
                    if numeroMagico == 0xd4c3b2a1:
                        self.ordenBytes = "<"
                    elif numeroMagico == 0xa1b2c3d4:
                        self.ordenBytes = ">"
                    else:
                        raise ValueError("Formato pcap no reconocido o endianness no soportado.")
                    self.archivo.seek(self.posicionArchivo) # Volver a la posición guardada
            return self
        except FileNotFoundError:
            print(f"Error: El archivo '{self.rutaArchivo}' no fue encontrado.")
            raise
        except ValueError as error_valor:
            print(f"Error al leer la cabecera global del pcap: {error_valor}")
            raise
        except Exception as error:
            print(f"Ocurrió un error al abrir el archivo pcap: {error}")
            raise

    def cerrar(self):
        if self.archivo:
            self.posicionArchivo = self.archivo.tell()
            self.archivo.close()
            self.archivo = None

    def leerSiguientePaquete(self):
        if self.archivo and self.ordenBytes:
            cabeceraPaquete = self.archivo.read(16)
            if len(cabeceraPaquete) < 16:
                return None
            try:
                _, _, longitudIncluida, _ = struct.unpack(self.ordenBytes + "IIII", cabeceraPaquete)
                datosPaquete = self.archivo.read(longitudIncluida)
                self.indiceActual += 1
                self.posicionArchivo = self.archivo.tell()
                if len(datosPaquete) < longitudIncluida:
                    print(f"Advertencia: Lectura incompleta del paquete número {self.indiceActual + 1}.")
                    return None

                return datosPaquete
            except struct.error:
                return None # Error al desempaquetar la cabecera (posible fin de archivo)
        return None

    def volverAlPrimerPaquete(self):
        if self.archivo:
            self.archivo.seek(24)  # Volver después de la cabecera global
            self.indiceActual = 0
            self.posicionArchivo = 24
            return True
        return False



