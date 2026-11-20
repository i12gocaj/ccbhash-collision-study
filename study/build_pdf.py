"""Render the reviewed Markdown manuscript as a typeset, searchable PDF."""
from common import *
import re
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape
import markdown
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, Preformatted, KeepTogether, PageBreak, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT,TA_RIGHT
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

OUT=ROOT/'output/pdf';OUT.mkdir(parents=True,exist_ok=True)
SOURCE=ROOT/'output/ESTUDIO_CCBHASH.md'
# Windows fonts used for the distributed PDF; on macOS the closest installed
# equivalents (Segoe UI is not available there, so Arial replaces it).
WINDOWS=Path('C:/Windows/Fonts');MAC=Path('/System/Library/Fonts/Supplemental');WORD=Path('/Applications/Microsoft Word.app/Contents/Resources/DFonts')
FONTS={'Study':[WINDOWS/'georgia.ttf',MAC/'Georgia.ttf'],'Study-Bold':[WINDOWS/'georgiab.ttf',MAC/'Georgia Bold.ttf'],
       'Study-Italic':[WINDOWS/'georgiai.ttf',MAC/'Georgia Italic.ttf'],'Study-BoldItalic':[WINDOWS/'georgiaz.ttf',MAC/'Georgia Bold Italic.ttf'],
       'Study-Mono':[WINDOWS/'consola.ttf',WORD/'Consola.ttf',MAC/'Courier New.ttf'],
       'Study-Sans':[WINDOWS/'segoeui.ttf',MAC/'Arial.ttf'],'Study-SansBold':[WINDOWS/'seguisb.ttf',MAC/'Arial Bold.ttf']}
for name,candidates in FONTS.items():
    file=next((f for f in candidates if f.is_file()),None)
    assert file is not None,f'No font available for {name}: {candidates}'
    pdfmetrics.registerFont(TTFont(name,str(file)))
pdfmetrics.registerFontFamily('Study',normal='Study',bold='Study-Bold',italic='Study-Italic',boldItalic='Study-BoldItalic')
styles=getSampleStyleSheet()
NAVY=colors.HexColor('#183c52');BURGUNDY=colors.HexColor('#934854');INK=colors.HexColor('#243038');PAPER=colors.HexColor('#f5f2ed')
styles.add(ParagraphStyle('StudyBody',fontName='Study',fontSize=10.4,leading=15.2,spaceAfter=8,textColor=INK))
styles.add(ParagraphStyle('StudyTitle',fontName='Study',fontSize=34,leading=44,spaceAfter=23,textColor=NAVY,keepWithNext=True))
styles.add(ParagraphStyle('StudyHeading',fontName='Study-SansBold',fontSize=14,leading=19,spaceBefore=15,spaceAfter=9,textColor=NAVY,keepWithNext=True))
styles.add(ParagraphStyle('StudySectionNumber',fontName='Study-SansBold',fontSize=17,leading=22,textColor=colors.white))
styles.add(ParagraphStyle('StudySectionTitle',parent=styles['StudyHeading'],spaceBefore=0,spaceAfter=0))
styles.add(ParagraphStyle('StudySubheading',fontName='Study-Bold',fontSize=10.7,leading=16,spaceBefore=11,spaceAfter=7,textColor=BURGUNDY,keepWithNext=True))
styles.add(ParagraphStyle('StudyCell',fontName='Study-Sans',fontSize=9.1,leading=12.5,textColor=INK))
styles.add(ParagraphStyle('StudyHeaderCell',fontName='Study-SansBold',fontSize=9.1,leading=12.5,textColor=colors.white))
styles.add(ParagraphStyle('StudyNumber',parent=styles['StudyCell'],alignment=TA_RIGHT))
styles.add(ParagraphStyle('StudyCaption',parent=styles['StudyBody'],fontSize=9.7,leading=13,spaceAfter=12))
styles.add(ParagraphStyle('StudyList',parent=styles['StudyBody'],leftIndent=13,firstLineIndent=-8,spaceAfter=6))
styles.add(ParagraphStyle('StudyCode',fontName='Study-Mono',fontSize=8.1,leading=11.1,spaceAfter=10))

def typeset_text(value):
    text=escape(value or '')
    for character,markup in [('ᵇ','<super>b</super>'),('ᵢ','<sub>i</sub>'),('⁻','<super>−</super>'),('ⱼ','<sub>j</sub>')]:
        text=text.replace(character,markup)
    return text

def inline(node):
    text=typeset_text(node.text)
    for child in node:
        inner=inline(child)
        if child.tag in ('strong','b'):text+='<b>'+inner+'</b>'
        elif child.tag in ('em','i'):text+='<i>'+inner+'</i>'
        elif child.tag=='code':
            size=7.7 if len(''.join(child.itertext()))>45 else 8.6
            text+=f'<font name="Study-Mono" size="{size}">'+inner+'</font>'
        elif child.tag=='a':text+='<a href="'+escape(child.attrib['href'],{'"':'&quot;'})+'" color="#246b73">'+inner+'</a>'
        elif child.tag=='br':text+='<br/>'
        else:text+=inner
        text+=typeset_text(child.tail)
    return text

html=markdown.markdown(SOURCE.read_text(encoding='utf-8'),extensions=['tables','fenced_code'])
tree=ET.fromstring('<root>'+html+'</root>')
story=[];width=A4[0]-108;pending_figure=None
for node in tree:
    if pending_figure is not None:
        assert node.tag=='p' and ''.join(node.itertext()).startswith('Figura '),'Every figure must have an adjacent caption'
    if node.tag in ('h1','h2','h3'):
        if ''.join(node.itertext()) in ('Resumen','Referencias'):story.append(PageBreak())
        if node.tag=='h1':story.append(Spacer(1,93))
        value='Estudio de colisiones<br/>de CCBHash' if node.tag=='h1' else inline(node)
        numbered=re.match(r'^(\d+)\. (.+)$',value) if node.tag=='h2' else None
        if numbered:
            story.append(Spacer(1,13))
            heading=Table([[Paragraph(numbered[1],styles['StudySectionNumber']),Paragraph(numbered[2],styles['StudySectionTitle'])]],colWidths=[31,width-31])
            heading.setStyle(TableStyle([('BACKGROUND',(0,0),(0,0),BURGUNDY),('VALIGN',(0,0),(-1,-1),'MIDDLE'),('LEFTPADDING',(0,0),(0,0),8),('LEFTPADDING',(1,0),(1,0),10),('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4)]))
            heading.keepWithNext=True
            spacing=Spacer(1,9);spacing.keepWithNext=True
            story.extend([heading,spacing])
        else:story.append(Paragraph(value,styles['StudyTitle' if node.tag=='h1' else 'StudySubheading' if node.tag=='h3' else 'StudyHeading']))
    elif node.tag=='p':
        img=node.find('img')
        if img is not None:
            path=SOURCE.parent/img.attrib['src']
            image_width=min(width,465)
            from PIL import Image as PILImage
            with PILImage.open(path) as p:ratio=p.height/p.width
            pending_figure=[Image(str(path),width=image_width,height=image_width*ratio),Spacer(1,4)]
        else:
            style=styles['StudyCaption'] if (''.join(node.itertext()).startswith('Figura ')) else styles['StudyBody']
            paragraph=Paragraph(inline(node),style)
            next_index=list(tree).index(node)+1
            if next_index<len(tree) and tree[next_index].tag=='pre':paragraph.keepWithNext=True
            if pending_figure is not None:
                story.append(KeepTogether([*pending_figure,paragraph]));pending_figure=None
            elif ''.join(node.itertext()).startswith('La conclusión es directa:'):
                highlight=Table([[paragraph]],colWidths=[width])
                highlight.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#e6eeeb')),('LINEBEFORE',(0,0),(0,-1),3,colors.HexColor('#246b73')),('LEFTPADDING',(0,0),(-1,-1),12),('RIGHTPADDING',(0,0),(-1,-1),12),('TOPPADDING',(0,0),(-1,-1),10),('BOTTOMPADDING',(0,0),(-1,-1),10)]))
                story.extend([KeepTogether([highlight]),Spacer(1,10)])
            else:story.append(paragraph)
    elif node.tag in ('ul','ol'):
        for index,item in enumerate(node.findall('li'),start=1):
            prefix=f'{index}. ' if node.tag=='ol' else '- '
            story.append(Paragraph(prefix+inline(item),styles['StudyList']))
    elif node.tag=='pre':
        text=''.join(node.itertext()).rstrip()
        story.append(Preformatted(text,styles['StudyCode'],maxLineLength=95))
    elif node.tag=='table':
        rows=node.findall('.//tr')
        numeric_columns={j for j in range(1,len(rows[0])) if all(re.fullmatch(r'[0-9][0-9.,% ]*',''.join(row[j].itertext())) for row in rows[1:])}
        data=[[Paragraph(inline(cell),styles['StudyHeaderCell' if i==0 else 'StudyNumber' if j in numeric_columns else 'StudyCell']) for j,cell in enumerate(row)] for i,row in enumerate(rows)]
        n=len(data[0])
        if n==2: col_widths=[width*.56,width*.44]
        elif n==3:col_widths=[width*.42,width*.36,width*.22]
        elif n==4:col_widths=[width*.34,width*.18,width*.20,width*.28]
        else:col_widths=[width*.29]+[width*.71/(n-1)]*(n-1)
        table=Table(data,colWidths=col_widths,repeatRows=1,hAlign='LEFT')
        table.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,0),NAVY),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,PAPER]),
            ('LINEBELOW',(0,-1),(-1,-1),.5,colors.HexColor('#b5c4cb')),
            ('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),6),
            ('RIGHTPADDING',(0,0),(-1,-1),6),('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5),
        ]))
        # Keep short result tables intact so their header and result rows are read together.
        story.extend([KeepTogether([table]) if len(data)<=8 else table,Spacer(1,10)])

assert pending_figure is None

def footer(c,doc):
    c.saveState()
    if doc.page==1:
        c.setFillColor(PAPER);c.rect(0,0,A4[0],A4[1],fill=1,stroke=0)
        # Canvas is painted before flowables; the title and subtitle stay searchable.
        c.setFillColor(BURGUNDY);c.rect(54,A4[1]-101,53,3,fill=1,stroke=0)
        c.setFont('Study-SansBold',10);c.setFillColor(NAVY)
        c.drawString(54,A4[1]-80,'INVESTIGACIÓN · SIMILITUD DE FUNCIONES')
        c.setFont('Study-Italic',13);c.setFillColor(INK)
        c.drawString(64,468,'3x - 1');c.drawString(64,433,'3x + 2')
        c.setStrokeColor(BURGUNDY);c.setLineWidth(1.2)
        c.line(132,471,243,451);c.line(132,436,243,451)
        c.setStrokeColor(colors.HexColor('#246b73'));c.setFillColor(colors.HexColor('#246b73'));c.circle(273,451,25,fill=1,stroke=1)
        c.setFont('Study-SansBold',16);c.setFillColor(colors.white);c.drawCentredString(273,446,'13')
        c.setStrokeColor(colors.HexColor('#246b73'));c.line(302,451,405,451)
        c.line(399,455,405,451);c.line(399,447,405,451)
        c.setFont('Study-SansBold',12);c.setFillColor(BURGUNDY);c.drawString(416,447,'Firma igual')
        c.setFont('Study-Sans',8.6);c.setFillColor(INK)
        c.drawString(54,393,'Retornos distintos');c.drawCentredString(273,393,'Componentes iguales');c.drawString(416,393,'Colisión completa')
        y=248;column=(A4[0]-108)/3
        c.setFillColor(NAVY);c.rect(54,225,A4[0]-108,105,fill=1,stroke=0)
        for i,(value,label) in enumerate([('256','funciones con firma idéntica'),('5.489','perfiles del corpus público'),('16','bits por digest textual')]):
            x=66+i*column
            c.setFont('Study',31);c.setFillColor(colors.HexColor(['#c8e1d6','#ead6a7','#efc8cf'][i]));c.drawString(x,y+15,value)
            c.setFont('Study-Sans',8.1);c.setFillColor(colors.white);c.drawString(x,y-8,label)
        c.setFont('Study-Sans',10);c.setFillColor(NAVY)
        c.drawString(54,104,'Código y resultados reproducibles')
        c.setFont('Study-Sans',8.5);c.drawString(54,83,'6 de octubre de 2026')
    else:
        c.setStrokeColor(colors.HexColor('#d5dfe3'));c.line(54,42,A4[0]-54,42)
        c.setFont('Study-Sans',8);c.setFillColor(colors.HexColor('#60717b'))
        c.drawString(54,27,'CCBHash · Estudio de colisiones')
        c.drawRightString(A4[0]-54,27,str(doc.page))
    c.restoreState()

path=OUT/'ESTUDIO_CCBHASH.pdf'
doc=SimpleDocTemplate(str(path),pagesize=A4,rightMargin=54,leftMargin=54,topMargin=50,bottomMargin=52,
                      title='Estudio de colisiones de CCBHash',
                      subject='Análisis experimental y matemático de colisiones con evidencia reproducible',invariant=1)
doc.build(story,onFirstPage=footer,onLaterPages=footer)
from pypdf import PdfReader
reader=PdfReader(str(path));text='\n'.join(page.extract_text() for page in reader.pages)
assert '32.640' in text and '109.277' in text and len(reader.pages)>5
dump(ROOT/'study/results/pdf_checks.json',dict(pages=len(reader.pages),characters=len(text),text_extraction='passed',visual_review='pending'))
print(canonical(dict(pdf=str(path),pages=len(reader.pages),characters=len(text))))
