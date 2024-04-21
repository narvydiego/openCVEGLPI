# openCVEGLPI
Este es el código que está siendo generado para obtener los activos de un servidor GLPI y posteriormente identificar las vulnerabilidades conocidas de cada activo mediante openCVE. El código está desarrollado en Python con ayuda de las API de los servidores antes mencionados.

## Estructura de código
1. **activosMicroRed.py:** Es el código principal que contiene el `main` para ejecutar el proyecto.
2. **interGLPIAPI.py:** Sirve para la interacción entre nuestro proyecto y la API de GLPI para obtener los activos en base a categorías del Laboratorio.
3. **ipScanner.py:** Realiza el escaneo de direcciones IP mediante un listado de direcciones MAC, esto se hace mediante el uso de mensajes ARP.
4. **interopenCVEAPI.py:** Realiza el escaneo de CVE de los activos de la MicroRed utilizando openCVE y envía las vulnerabilidades conocidas.
5. **GLPICVE.py:** Código de referencia para realizar pruebas.

## Requisitos
1. Nmap
2. Python
3. GLPI
4. API en OpenCVE
5. Librería Scapy
6. Librería ReportLab
