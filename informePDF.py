"""
Universidad de Cuenca - Ingeniería en Telecomunicaciones
Trabajo de Titulación - 2024: Implementacion de un Framework para pentesting en el laboratorio de MicroRed de la Universidad de Cuenca
Autores: Diego Narvaez, Fabricio Malla
Este es el modulo ayuda en la impresion de los datos obtenidos en un archivo PDF
"""
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase.pdfmetrics import stringWidth
import datetime

def addHeader(c):
    width, height = letter  # Tamaño de página
    image_path = 'logoUCuenca.png'
    image = ImageReader(image_path)
    c.drawImage(image, 50, 740, width=100, height=50)  # Ajusta la posición y tamaño según necesites
    
    header_text = "Universidad de Cuenca"
    sub_header_text = "Informe de Activos, Laboratorio de MicroRed de la Universidad de Cuenca"
    text_width = stringWidth(header_text, 'Helvetica', 14)
    sub_text_width = stringWidth(sub_header_text, 'Helvetica', 12)
    
    text_x = 150 + (width - 150 - text_width) / 2
    sub_text_x = 150 + (width - 150 - sub_text_width) / 2
    
    c.setFont("Helvetica-Bold", 14)
    c.drawString(text_x, 760, header_text)
    c.setFont("Helvetica", 12)
    c.drawString(sub_text_x, 745, sub_header_text)
    
    c.line(50, 730, width - 50, 730)  # Añadir línea debajo del encabezado

def print_dictionary_content(c, data_dict):
    c.setFont("Helvetica", 12)
    y_position = 710  # Inicializar la posición y desde donde se empieza a imprimir el diccionario

    for category, items in data_dict.items():
        c.drawString(50, y_position, f"{category}:")
        y_position -= 20  # Ajustar la posición y para la primera entrada del arreglo

        for item in items:
            c.drawString(70, y_position, f"- {item}")
            y_position -= 20  # Ajustar la posición y para la siguiente entrada
        
        y_position -= 10  # Espacio extra antes de la siguiente categoría

if __name__ == "__main__":
    fecha = datetime.date.today()
    c = canvas.Canvas(f"informeActivosMicroRed{fecha}.pdf", pagesize=letter)
    addHeader(c)
    
    # Ejemplo de diccionario
    data_dict = {
        "Categoría 1": ["Item 1", "Item 2", "Item 3"],
        "Categoría 2": ["Item A", "Item B"],
        "Categoría 3": ["Item X", "Item Y", "Item Z"]
    }

    print_dictionary_content(c, data_dict)
    c.save()