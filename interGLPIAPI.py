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
    
# Funcion para seleccionar una categoria de activos
def select_category(categories):
    print("Por favor, selecciona una categoría:")
    for i, category in enumerate(categories, 1):
        print(f"{i}. {category}")

    selected = int(input("Ingresa el número de la categoría: ")) - 1

    if 0 <= selected < len(categories):
        return categories[selected]
    else:
        print("Selección inválida. Por favor, intenta de nuevo.")
        return select_category(categories)

# Funcion para obtener los activos de GLPI
def get_assets_glpi(urlGLPI, headers, category):
    response = requests.get(urlGLPI + f'/{category}', headers=headers)
    if response.status_code != 200:
        raise Exception(f"Respuesta Fallida con status: {response.status_code}")
    try:
        assets = response.json()
    except json.JSONDecodeError:
        raise Exception("Respuesta no es un JSON valido")
    
    return assets

def interGLPIAPI(urlGLPI, appTokenGLPI, userToken):
    # Categoria de activos en GLPI
    categories = ['Computer', 'NetworkEquipment', 'Peripheral', 'Phone', 'Printer', 'Software', 'Storage', 'User', 'VirtualMachine']
    sessionTokenGLPI = get_session_token(appTokenGLPI, userToken, urlGLPI)
    if sessionTokenGLPI:
        print("Inicio de Sesion con GLPI establecida con exito")
        # Encabezados para las peticiones a GLPI
        headersGLPI = {
            "App-Token": appTokenGLPI,
            "Content-Type": "application/json",
            "Session-Token": sessionTokenGLPI
        }
        # Peticion para obtener los activos de GLPI
        category = select_category(categories)
        print(f"Has seleccionado: {category}")
        assetsGLPI = get_assets_glpi(urlGLPI, headersGLPI, category)
        asset_data = []
        for asset in assetsGLPI:
            idAsset = asset.get('id')
            nameAsset = asset.get('name')
            linksAsset = asset.get('links')
            for link in linksAsset:
                rel = link.get('rel')
                if rel == 'NetworkPort':
                    href = link.get('href')
                    response = requests.get(href, headers=headersGLPI)
                    networkPorts = response.json()
                    if networkPorts != []:
                        for networkPort in networkPorts:
                            mac = networkPort.get('mac')
                            if mac != None and mac != "00:00:00:00:00:00":
                                asset_data.append({"id": idAsset, "name": nameAsset, "mac": mac})                                 
        return asset_data

