import json

class export_to_JSON:
    def escribirJson(self,infoParaGuardar):
        archivoJSON = 'paqueteProcesado'
        with open(archivoJSON,'w') as archivoJSON:
            json.dump(infoParaGuardar, archivoJSON, indent=4)



