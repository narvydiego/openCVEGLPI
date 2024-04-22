"""
Universidad de Cuenca - Ingeniería en Telecomunicaciones
Trabajo de Titulación - 2024: Implementacion de un Framework para pentesting en el laboratorio de MicroRed de la Universidad de Cuenca
Autores: Diego Narvaez, Fabricio Malla
Este es el modulo principal para la obtencion de los activos de GLPI y sus respectivos CVEs
"""

import interGLPIAPI as iglpiapi
import interopenCVEAPI as iopenCVEapi
import ipScanner as ipScan
import informePDF as iPDF
import csv

# Diccionario para ejemplo de datos de activos
ejempData = {
  "Computer": [
    {
      "id": "101",
      "name": "Laptop Lenovo ThinkPad",
      "model": "ThinkPad X1 Carbon",
      "type": "Laptop",
      "mac": ["00:A0:C9:18:C8:BB"]
    },
    {
      "id": "102",
      "name": "Desktop HP Envy",
      "model": "Envy 750-514",
      "type": "Desktop",
      "mac": ["00:A0:C9:43:F3:C1"]
    }
  ],
  "NetworkEquipment": [
    {
      "id": "201",
      "name": "Cisco Switch",
      "model": "SG350-28",
      "type": "Switch",
      "mac": ["00:A0:C9:23:A5:B9"]
    },
    {
      "id": "202",
      "name": "Netgear Router",
      "model": "Nighthawk X6",
      "type": "Router",
      "mac": ["00:A0:C9:59:01:CF"]
    }
  ],
  "Peripheral": [
    {
      "id": "301",
      "name": "Logitech Mouse",
      "model": "MX Master 3",
      "type": "Mouse",
      "mac": []  
    },
    {
      "id": "302",
      "name": "Dell Monitor",
      "model": "U2718Q",
      "type": "Monitor",
      "mac": []  
    }
  ]
}

ejempData2 = {
    "Computer": [
        {
            "id": "101",
            "name": "Servidor SCADA",
            "model": "Dell PowerEdge R740",
            "type": "Servidor Industrial",
            "mac": [
                "00:A0:C9:18:C8:BB",  
                "00:A0:C9:18:C8:BC", 
                "00:A0:C9:18:C8:BD"  
            ],
            "ip": ["192.168.1.101", "192.168.1.102"]  
        },
        {
            "id": "102",
            "name": "Workstation para Ingeniería",
            "model": "HP Z4 G4",
            "type": "Workstation",
            "mac": ["00:A0:C9:43:F3:C1"],
            "ip": []  
        }
    ],
    "NetworkEquipment": [
        {
            "id": "201",
            "name": "Switch Ethernet Industrial",
            "model": "Siemens SCALANCE X208",
            "type": "Switch Industrial",
            "mac": ["00:A0:C9:23:A5:B9"],
            "ip": ["192.168.1.200"]  
        },
        {
            "id": "202",
            "name": "Router Industrial",
            "model": "Cisco IE-4010",
            "type": "Router Industrial",
            "mac": ["00:A0:C9:59:01:CF"],
            "ip": []  
        }
    ],
    "Peripheral": [
        {
            "id": "301",
            "name": "HMI Touch Screen",
            "model": "Siemens SIMATIC HMI",
            "type": "HMI",
            "mac": ["00:A0:C9:60:11:22"],
            "ip": ["192.168.1.50"]  
        },
        {
            "id": "302",
            "name": "Impresora de Etiquetas Industrial",
            "model": "Zebra ZT230",
            "type": "Impresora Industrial",
            "mac": ["00:A0:C9:31:41:51"],
            "ip": []  
        }
    ]
}


data3 = {
    'Computer': [
        {
            'id': '101',
            'name': 'Servidor SCADA',
            'model': 'Dell PowerEdge R740',
            'type': 'Servidor Industrial',
            'mac': ['00:A0:C9:18:C8:BB', '00:A0:C9:18:C8:BC', '00:A0:C9:18:C8:BD'],
            'ip': ['192.168.1.101', '192.168.1.102'],
            'cve': []
        },
        {
            'id': '102',
            'name': 'Workstation para Ingeniería',
            'model': 'HP Z4 G4',
            'type': 'Workstation',
            'mac': ['00:A0:C9:43:F3:C1'],
            'ip': [],
            'cve': []
        }
    ],
    'NetworkEquipment': [
        {
            'id': '201',
            'name': 'Switch Ethernet Industrial',
            'model': 'Siemens SCALANCE X208',
            'type': 'Switch Industrial',
            'mac': ['00:A0:C9:23:A5:B9'],
            'ip': ['192.168.1.200'],
            'cve': []
        },
        {
            'id': '202',
            'name': 'Router Industrial',
            'model': 'Cisco IE-4010',
            'type': 'Router Industrial',
            'mac': ['00:A0:C9:59:01:CF'],
            'ip': [],
            'cve': []
        }
    ],
    'Peripheral': [
        {
            'id': '301',
            'name': 'HMI Touch Screen',
            'model': 'Siemens SIMATIC HMI',
            'type': 'HMI',
            'mac': ['00:A0:C9:60:11:22'],
            'ip': ['192.168.1.50'],
            'cve': ['CVE-2015-2822', 'CVE-2015-2823']
        },
        {
            'id': '302',
            'name': 'Impresora de Etiquetas Industrial',
            'model': 'Zebra ZT230',
            'type': 'Impresora Industrial',
            'mac': ['00:A0:C9:31:41:51'],
            'ip': [],
            'cve': []
        }
    ]
}

# Funcion para crear archivos CSV con los activos obtenidos
def createCSV(dataAssetes, filename):
    with open (filename, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["ID", "Name", "Model", "Type", "MAC Addresses", "IP Addresses", "CVEs"])
        for category, assets in dataAssetes.items():
            for asset in assets:
                writer.writerow([asset['id'], asset['name'], asset['model'], asset['type'], asset['mac'], asset['ip'], asset['cve']])

# Funcion para obtener las direcciones IP en archivo TXT
def createTXT(dataAssets, filename):
    with open (filename, 'w') as file:
        file.write("Name, IP Address\n")
        for category, assets in dataAssets.items():
            for asset in assets:
                if asset['ip']:
                    for ip in asset['ip']:
                        file.write(f"{asset['name']}, {ip}\n")

# Funcion para obtener datos de archivo txt
def get_info_txt():
    neceInfo = {}
    with open('requirements.txt', 'r') as archivo:
        for linea in archivo:
            partes = linea.strip().split('=')
            if len(partes) == 2:
                clave, data = partes
                verData = data.split(',')
                if len(verData) == 1:
                    neceInfo[clave] = data
                else:
                    neceInfo[clave] = verData
            elif len(partes) == 3:
                neceInfo[partes[0]] = partes[1] + '='
    return neceInfo

# Funcion para integrar los datos de los activos y los CVEs
def intDataCVE(assetsData, cveData, categories):
    modelos = [item['model'] for item in cveData]
    print(modelos)
    for category in categories:
        assetsCategory = assetsData[category]
        for asset in assetsCategory:
            for cve in cveData:
                if asset['model'] == cve['model']:
                    asset['cve'] = cve['cve']
    return assetsData


# Funcion principal del proyecto
if __name__ == "__main__":
    verNecInfo = ["urlGLPI", "appTokenGLPI", "userToken", "networkAssets", "openCVEURL", "usernameOpenCVE", "passOpenCVE"]
    #categories = ['Computer', 'NetworkEquipment', 'Peripheral', 'Software', 'VirtualMachine']
    categories = ['Computer', 'NetworkEquipment', 'Peripheral']
    neceInfo = {} # Diccionario para almacenar la informacion necesaria para el proyecto
    neceInfo = get_info_txt() 
    # Comprobar la información ingresada en requirements.txt
    if set(verNecInfo) == set(neceInfo.keys()):
        print("Datos en requirements.txt correctamente ingresados!!!!")
        print("1. Proceso de obtencion de activos de GLPI")
        assetsData = iglpiapi.interGLPIAPI(neceInfo['urlGLPI'], neceInfo['appTokenGLPI'], neceInfo['userToken'], categories)
        print("2. Proceso de obtencion de direcciones Ip en base a las direcciones MAC")
        ip = ipScan.ipScanner(assetsData, verNecInfo['networkAssets'], categories)
        print("3. Proceso de obtencion de CVEs")
        cveData = iopenCVEapi.interopenCVEAPI(ejempData2, neceInfo['openCVEURL'], neceInfo['usernameOpenCVE'], neceInfo['passOpenCVE'], categories)
        print(cveData)
        data = intDataCVE(ejempData2, cveData, categories)
        print("Diccioario antes de la impresion")
        print(data)
        print("4. Impresion de los datos obtenidos en un archivo PDF")
        iPDF.informePDF(data3, "Informe_Activos_MicroRed")
        createCSV(data3, "Activos_MicroRed.csv")
        createTXT(data3, "IP_MicroRed.txt")
    else:
        print("Datos en requirements.txt ingresados erroneamente!!!")
        faltInfo = [falt for falt in set(verNecInfo) if falt not in set(neceInfo.keys())]
        print(f"Datos Faltantes: \n {faltInfo}")    