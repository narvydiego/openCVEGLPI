"""
Universidad de Cuenca - Ingeniería en Telecomunicaciones
Trabajo de Titulación - 2024: Implementacion de un Framework para pentesting en el laboratorio de MicroRed de la Universidad de Cuenca
Autores: Diego Narvaez, Fabricio Malla
Obtencion de los errores CVE en base a la lista de nombres de activos de la MicroRed
"""
import requests
from requests.auth import HTTPBasicAuth

def assetsModels(assetsData):
    assetNames = set()
    for asset in assetsData:
        if 'model' in asset:
            assetName = asset['model']
            assetNames.add(assetName)
    return assetNames

def interopenCVEAPI(assetsData, openCVEURL, username, password):
    assetNames = assetsModels(assetsData)
    cveData = []
    for name in assetNames:
        print(f"Buscando CVE para {name}")
        response = requests.get(openCVEURL + name, auth=HTTPBasicAuth(username, password))
        if response.status_code == 200:
            cveResponse = response.json()
            cve = {'model': name, 'cve': cveResponse}
            cveData.append(cve)
        else:
            print(f"Error al obtener los datos de CVE para {name}")
    return cveData