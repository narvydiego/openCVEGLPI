"""
Universidad de Cuenca - Ingeniería en Telecomunicaciones
Trabajo de Titulación - 2024: Implementacion de un Framework para pentesting en el laboratorio de MicroRed de la Universidad de Cuenca
Autores: Diego Narvaez, Fabricio Malla
Main para la obtencion de CVE en base a los activos de la MicroRed API de GLPI y OpenCVE
"""
import interGLPIAPI as iglpiapi
import ipScanner as ips

assetsPrueba = {
    'id': 9,
    'name': 'microredcs', 
    'mac': '00:0c:29:07:60:23'}
#00:0c:29:07:60:23 f0:77:c3:07:57:97
if __name__ == '__main__':
    urlGLPI =  "http://192.168.222.57/apirest.php" 
    appTokenGLPI = "waXuGxupcV5xpHJbLu81bIgzypHdgIQfYJSS8qmZ"
    userToken = "PMujBIXnMJvnHyyqcmd0u17whdihRatbtHCCZ5TM"
    networkAssets = ["192.168.222.0/24", "192.168.244.0/24"]
    assetsData = iglpiapi.interGLPIAPI(urlGLPI, appTokenGLPI, userToken)
    print(assetsData)
    ip = ips.ipScanner(assetsPrueba, networkAssets)
    print(ip)