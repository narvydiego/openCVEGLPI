"""
Universidad de Cuenca - Ingeniería en Telecomunicaciones
Trabajo de Titulación - 2024: Implementacion de un Framework para pentesting en el laboratorio de MicroRed de la Universidad de Cuenca
Autores: Diego Narvaez, Fabricio Malla
Modulo para Lectura de Direcciones IP en los activos de la MicroRed en base a las direciones MAC
"""
from scapy.all import ARP, Ether, srp

def ipScanner(assets, ipRanges):
    for asset in assets:
        if 'mac' in asset:
            macAddress = asset['mac']
            ipRespose = []
            for mac in macAddress:
                for ipRange in ipRanges:
                    arp = ARP(pdst = ipRange)
                    ether = Ether(dst = "ff:ff:ff:ff:ff:ff")
                    packet = ether/arp
                    result = srp(packet, timeout = 3, verbose = 0)[0]
                    # Buscando la direccion IP en las respuestas
                    for sent, received in result:
                        if received.hwsrc == mac:
                            ipRespose.append(received.psrc)
            asset['ip'] = ipRespose
    return assets