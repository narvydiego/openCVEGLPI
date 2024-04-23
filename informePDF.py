"""
Universidad de Cuenca - Ingeniería en Telecomunicaciones
Trabajo de Titulación - 2024: Implementacion de un Framework para pentesting en el laboratorio de MicroRed de la Universidad de Cuenca
Autores: Diego Narvaez, Fabricio Malla
Este es el modulo ayuda en la impresion de los datos obtenidos en un archivo PDF
"""
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, LongTable, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
import datetime
import os

def wrap_text(text, max_chars):
    """ Ajusta el texto para que no exceda el máximo de caracteres permitidos, añadiendo saltos de línea. """
    words = text.split()
    lines = []
    current_line = ""
    for word in words:
        if len(current_line) + len(word) + 1 > max_chars:
            lines.append(current_line)
            current_line = word + " "
        else:
            current_line += word + " "
    lines.append(current_line.strip())
    return '\n'.join(lines)

def header(canvas, doc):
    """ Crea un encabezado para cada página """
    canvas.saveState()
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

    for category, assets in data_assets.items():
        Story.append(Paragraph(category, styles['Heading2']))
        table_data = [['ID', 'Name', 'Model', 'Type', 'MAC Addresses', 'IP Addresses', 'CVEs']]
        for asset in assets:
            row = [
                asset.get('id', ''), 
                wrap_text(asset.get('name', ''), 12),  
                wrap_text(asset.get('model', ''), 15), 
                wrap_text(asset.get('type', ''), 12),  
                '\n'.join(asset.get('mac', [])),  
                '\n'.join(asset.get('ip', [])),  
                '\n'.join(asset.get('cve', []))  
            ]
            table_data.append(row)

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

    doc.build(Story, onFirstPage=header, onLaterPages=header)