import json

class export_to_JSON:
    def escribirJson(self,listaPaquetesDis):
        archivoJSON = 'paqueteProcesado'

        with open(archivoJSON,'w') as archivoJSON:
            for datos in listaPaquetesDis:
                json.dump(datos.getDissectedLayers(), archivoJSON, indent=4)



