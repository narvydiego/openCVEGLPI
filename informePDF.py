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
from reportlab.platypus import Table, TableStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase.pdfmetrics import stringWidth
import datetime

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

def addHeader(c):
    width, height = letter
    image_path = 'logoUCuenca.png'
    image = ImageReader(image_path)
    c.drawImage(image, 50, 740, width=100, height=50)
    
    header_text = "Universidad de Cuenca"
    sub_header_text = "Informe de Activos, Laboratorio de MicroRed"
    text_width = stringWidth(header_text, 'Helvetica', 14)
    sub_text_width = stringWidth(sub_header_text, 'Helvetica', 12)
    
    text_x = 150 + (width - 150 - text_width) / 2
    sub_text_x = 150 + (width - 150 - sub_text_width) / 2
    
    c.setFont("Helvetica-Bold", 14)
    c.drawString(text_x, 760, header_text)
    c.setFont("Helvetica", 12)
    c.drawString(sub_text_x, 745, sub_header_text)
    
    c.line(50, 730, width - 50, 730)

def draw_table(c, y_position, data_assets, top_margin=50, bottom_margin=50):
    width, height = letter
    c.setFont("Helvetica-Bold", 12)
    colWidths = [0.04 * width, 0.10 * width, 0.14 * width, 0.1 * width, 0.18 * width, 0.13 * width, 0.15 * width]

    for category, assets in data_assets.items():
        c.drawString(50, y_position, category)
        y_position -= 30

        table_data = [['ID', 'Name', 'Model', 'Type', 'MAC Addresses', 'IP Addresses', 'CVEs']]
        for asset in assets:
            row = [
                asset['id'],
                wrap_text(asset['name'], 12),
                wrap_text(asset['model'], 15),
                wrap_text(asset['type'], 12),
                '\n'.join(asset['mac']),
                '\n'.join(asset['ip']),
                '\n'.join(asset['cve'])
            ]
            table_data.append(row)

        table = Table(table_data, colWidths=colWidths)
        table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
            ('FONTSIZE', (0,0), (-1,-1), 10),
        ]))

        needed_height = table.wrap(width-100, height)[1]
        if y_position - needed_height < bottom_margin:
            c.showPage()
            addHeader(c) 
            y_position = height - top_margin 
        table.drawOn(c, 50, y_position - needed_height)
        y_position -= (needed_height + 20)


def informePDF(data_assets, filename):
    fecha = datetime.date.today()
    c = canvas.Canvas(f"{filename}_{fecha}.pdf", pagesize=letter)
    addHeader(c)
    y_position = 700
    draw_table(c, y_position, data_assets)
    c.save()

