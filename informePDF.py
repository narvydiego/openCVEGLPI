"""
Universidad de Cuenca - Ingeniería en Telecomunicaciones
Trabajo de Titulación - 2024: Implementacion de un Framework para pentesting en el laboratorio de MicroRed de la Universidad de Cuenca
Autores: Diego Narvaez, Fabricio Malla
Este es el modulo ayuda en la impresion de los datos obtenidos en un archivo PDF
"""
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, LongTable, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.utils import ImageReader
from reportlab.lib.styles import getSampleStyleSheet
import datetime
import os
import re

def wrap_text(text, max_chars):
    """ Ajusta el texto para que no exceda el máximo de caracteres permitidos, añadiendo saltos de línea.
    Se consideran espacios, guiones bajos y otros caracteres no alfabéticos como posibles puntos de ruptura. """
    # Separa por cualquier caracter no alfabético para mantener la legibilidad
    words = re.split('([_\W]+)', text)
    lines = []
    current_line = ""
    
    for word in words:
        # Verifica si añadir la palabra excede la longitud máxima
        if len(current_line + word) > max_chars:
            if current_line:  # Asegura no empezar con una línea vacía
                lines.append(current_line)
            # Si la palabra sola excede max_chars, se divide
            while len(word) > max_chars:
                lines.append(word[:max_chars])
                word = word[max_chars:]
            current_line = word
        else:
            current_line += word
    if current_line:  # Añade la última línea si no está vacía
        lines.append(current_line)

    return '\n'.join(lines)

def header(canvas, doc):
    """ Crea un encabezado para cada página que incluye texto e imagen. """
    canvas.saveState()
    # Configura la ubicación y el tamaño de la imagen
    image_path = 'logoUCuenca.png'  # Asegúrate de cambiar esto por la ruta real de tu imagen
    image = ImageReader(image_path)
    image_width = 100  # Ancho de la imagen en puntos
    image_height = 50  # Altura de la imagen en puntos
    image_x = 50  # Posición horizontal desde el borde izquierdo
    image_y = letter[1] - 60  # Posición vertical desde el borde superior
    
    # Dibuja la imagen
    canvas.drawImage(image, image_x, image_y, width=image_width, height=image_height, preserveAspectRatio=True, mask='auto')
    
    # Configura y dibuja el texto del encabezado
    canvas.setFont('Helvetica-Bold', 16)
    canvas.drawCentredString(letter[0] / 2, letter[1] - 30, "Universidad de Cuenca")
    canvas.setFont('Helvetica', 12)
    canvas.drawCentredString(letter[0] / 2, letter[1] - 50, "Informe de Activos, Laboratorio de MicroRed")
    canvas.line(50, letter[1] - 60, letter[0] - 50, letter[1] - 60)
    canvas.restoreState()


def informePDF(data_assets, folderPath, filename):
    fecha = datetime.date.today().isoformat()
    fullPath = os.path.join(folderPath, f"{filename}_{fecha}.pdf")
    doc = SimpleDocTemplate(fullPath, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)

    Story = []
    styles = getSampleStyleSheet()
    colWidths = [0.04 * letter[0], 0.10 * letter[0], 0.14 * letter[0], 0.1 * letter[0], 0.18 * letter[0], 0.13 * letter[0], 0.15 * letter[0]]
    Story.append(Paragraph("Activos de Laboratorio de MicroRed", styles['Heading1']))
    modelCVEDict = {}
    for category, assets in data_assets.items():
        Story.append(Paragraph(category, styles['Heading2']))
        #table_data = [['ID', 'Name', 'Model', 'Type', 'MAC Addresses', 'IP Addresses', 'CVEs']]
        table_data = [['ID', 'Name', 'Model', 'Type', 'MAC Addresses', 'IP Addresses']]
        for asset in assets:
            row = [
                asset.get('id', ''), 
                wrap_text(asset.get('name', ''), 12),  
                wrap_text(asset.get('model', ''), 15), 
                wrap_text(asset.get('type', ''), 12),  
                '\n'.join(asset.get('mac', [])),  
                '\n'.join(asset.get('ip', [])) 
                #'\n'.join(asset.get('cve', []))  
            ]
            table_data.append(row)
            model =asset.get('model', '')
            cve = asset.get('cve', [])
            if model not in modelCVEDict and cve != []:
                modelCVEDict[model] = cve
        table = LongTable(table_data, colWidths=colWidths)
        table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
        ]))
        Story.append(table)
        Story.append(Spacer(1, 12))
        
    Story.append(Paragraph("Listado de Activos con CVE encontrados en OpenCVE", styles['Heading1']))
    for model, cves in modelCVEDict.items():
        Story.append(Paragraph(model, styles['Heading2']))
        cve_text = ', '.join(cves)
        Story.append(Paragraph(cve_text, styles['BodyText']))
    doc.build(Story, onFirstPage=header, onLaterPages=header)