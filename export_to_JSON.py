import json

class export_to_JSON:
    def escribirJson(self,listaPaquetesDis):
        archivoJSON = 'paqueteProcesado.json'
        i = 0
        texto = "Paquete"
        listadatos = []
        for datos in listaPaquetesDis:
            i += 1
            listadatos.append(datos.getDissectedLayers())
        with open(archivoJSON,'w') as archivoJSON:
          json.dump(listadatos, archivoJSON, indent=4)


