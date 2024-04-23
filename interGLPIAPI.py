"""
Universidad de Cuenca - Ingeniería en Telecomunicaciones
Trabajo de Titulación - 2024: Implementacion de un Framework para pentesting en el laboratorio de MicroRed de la Universidad de Cuenca
Autores: Diego Narvaez, Fabricio Malla
Modulo para Interaccion con API de GLPI
"""
import requests

# Funcion para Iniciar sesion en GLPI
def get_session_token(appTokenGLPI, userToken, urlGLPI):
    headers = {
        "App-Token": appTokenGLPI,
        "Content-Type": "application/json",
        "Authorization": f"user_token {userToken}"
    }
    response = requests.get(urlGLPI + '/initSession', headers=headers)
    if response.text:
        session_info = response.json()
        return session_info.get('session_token')
    else:
        print("No se a podido establecer una sesion")
        return None

# Funcion para obtener los activos de GLPI
def get_assets_glpi(urlGLPI, headers, category):
    response = requests.get(urlGLPI + f'/{category}', headers=headers)
    if response.status_code != 200 and response.status_code != 206:
        raise Exception(f"Respuesta Fallida con status: {response.status_code}")
    try:
        assets = response.json()
    except json.JSONDecodeError:
        raise Exception("Respuesta no es un JSON valido")
    
    return assets

# Funcion para obtener modelo y tipo de activos de GLPI
def get_model_type(link, headersGLPI):
    href = link.get('href')
    response = requests.get(href, headers=headersGLPI)
    equipamentResponse = response.json()
    if equipamentResponse != []:
        name = equipamentResponse.get('name')
        if "product_number" in equipamentResponse:
            model = equipamentResponse.get('product_number')
            name = f"{name}{model}"
        return name
    return None
    

# Funcion para categorizar los datos obtenido de GLPI
def data_assets_glpi(assetsGLPI, category, headersGLPI):
    asset_data = []
    for asset in assetsGLPI:
        idAsset = asset.get('id')
        nameAsset = asset.get('name')
        linksAsset = asset.get('links')
        newAsset = {"id": idAsset, "name": nameAsset}
        for link in linksAsset:
            rel = link.get('rel')
            if rel == f'{category}Model':
                newAsset['model'] = get_model_type(link, headersGLPI)
                if newAsset['model'] == "Modicon TM251MESE1":
                    newAsset['model'] = "Modicon M251"
            elif rel == f'{category}Type':
                newAsset['type'] = get_model_type(link, headersGLPI)
            elif rel == 'NetworkPort':
                href = link.get('href')
                response = requests.get(href, headers=headersGLPI)
                networkPorts = response.json()
                if networkPorts != []:
                    direcMAC = []
                    for networkPort in networkPorts:
                        mac = networkPort.get('mac')
                        if mac != None and mac != "00:00:00:00:00:00":
                            direcMAC.append(mac)
                    newAsset['mac'] = direcMAC
        asset_data.append(newAsset)
    return asset_data

def interGLPIAPI(urlGLPI, appTokenGLPI, userToken, categories):
    # Categoria de activos en GLPI
    
    sessionTokenGLPI = get_session_token(appTokenGLPI, userToken, urlGLPI)
    if sessionTokenGLPI:
        print("Inicio de Sesion con GLPI establecida con exito")
        # Encabezados para las peticiones a GLPI
        headersGLPI = {
            "App-Token": appTokenGLPI,
            "Content-Type": "application/json",
            "Session-Token": sessionTokenGLPI
        }
        # Otencion de activos de GLPI categoria por categoria
        asset_data = {}
        for category in categories:
            print(f"Obteniendo activos de la categoria: {category}")
            assetsGLPI = get_assets_glpi(urlGLPI, headersGLPI, category)
            dataAssetNece = data_assets_glpi(assetsGLPI, category, headersGLPI)
            print(f"Activos obtenidos: {dataAssetNece}")
            asset_data[category] = dataAssetNece
        return asset_data

