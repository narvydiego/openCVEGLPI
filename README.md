# openCVEGLPI
Este es el código esta siendo generado para obtener los activos de un servidor GLPI para posteriormente obtener las vulnerabilidades conocidas de cada activo mediante openCVE, el código esta desarrollado en Python con ayuda de las API de los servidores antes mencionados.
## Estructura de código
1. **activosMicroRed.py:** Es el código principal que contiene el main para ejecutar el proyecto
2. **interGLPIAPI.py:** Sirve para la interacción entre nuestro proyecto y la API de GLPI para obtener los activos en base a categorias del Laboratorio
3. **ipScanner.py:** Realiza el escaneo de direcciones IP mediante un listado de direcciones MAC, esto es mediante el uso de mensajes ARP
4. **GLPICVE.py:** Código de referencia para realizar pruebas
