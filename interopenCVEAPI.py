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

def interopenCVEAPI(assetsData, openCVEURL, username, password, categories):
    cveData = [] 
    for category in categories:
        categoAssets = assetsModels(assetsData[category])   
        for asset in categoAssets:
            print(f"Buscando CVE para {asset}")
            reponse = requests.get(openCVEURL + asset, auth=HTTPBasicAuth(username, password))
            if reponse.status_code == 200:
                cveResponse = reponse.json()
                idCVE = []
                for respCVE in cveResponse:
                    idCVE.append(respCVE.get('id'))
                cve = {'model': asset, 'cve': idCVE}
                cveData.append(cve)
            else:
                print(f"Error al obtener los datos de CVE para {asset}")
    return cveData
    