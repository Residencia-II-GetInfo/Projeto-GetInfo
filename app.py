from flask import Flask, request, jsonify, render_template 
import base64
import os
import re
import time
import threading
import requests
import sqlite3
import xml.etree.ElementTree as ET
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

app = Flask(__name__)

# Configuração da API do Gmail
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
TOKEN_PATH = "token.json"
API_EXTERNA_URL = "https://sistema-externo.com/api/notas/"

# Inicializar banco de dados
conn = sqlite3.connect("notas_fiscais.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS notas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    numero TEXT UNIQUE,
                    emissor TEXT,
                    destinatario TEXT,
                    valor REAL,
                    data_emissao TEXT,
                    status TEXT DEFAULT 'pendente',
                    descricao TEXT
                )''')
conn.commit()

def verificar_emails():
    """Captura e-mails e verifica se possuem notas fiscais XML ou palavras-chave no corpo."""
    if not os.path.exists(TOKEN_PATH):
        print("Token de autenticação não encontrado.")
        return
    
    creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
    service = build("gmail", "v1", credentials=creds)
    results = service.users().messages().list(userId="me", q="is:unread", maxResults=10).execute()
    messages = results.get("messages", [])
    
    for message in messages:
        msg = service.users().messages().get(userId="me", id=message["id"]).execute()
        
        # Verifica se o corpo do e-mail contém palavras-chave indicando uma nota fiscal
        if verificar_corpo_email(msg):
            for part in msg.get("payload", {}).get("parts", []):
                if part.get("filename", "").endswith(".xml"):
                    data = part.get("body", {}).get("data")
                    if data:
                        xml_content = base64.urlsafe_b64decode(data).decode("utf-8")
                        nota = extrair_dados_xml(xml_content)
                        if nota:
                            capturar_nota(nota)
            
            # Marca o e-mail como lido
            service.users().messages().modify(userId="me", id=message["id"], body={"removeLabelIds": ["UNREAD"]}).execute()

def verificar_corpo_email(msg):
    """Verifica se o corpo do e-mail contém palavras-chave indicando uma nota fiscal."""
    body = ""
    for part in msg.get("payload", {}).get("parts", []):
        if part["mimeType"] == "text/plain":
            body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
            break

    # Lista de palavras-chave para indicar que o e-mail é relacionado a uma nota fiscal
    palavras_chave = ["nota fiscal", "NFe", "número da nota", "imposto", "nota eletrônica"]
    
    # Verifica se alguma palavra-chave está presente no corpo do e-mail
    if any(palavra in body.lower() for palavra in palavras_chave):
        print("Corpo do e-mail indica uma nota fiscal.")
        return True
    else:
        print("Corpo do e-mail não contém palavras-chave de nota fiscal.")
        return False

def extrair_dados_xml(xml_content):
    """Extrai informações essenciais de uma nota fiscal XML."""
    try:
        root = ET.fromstring(xml_content)
        ns = {'ns': 'http://www.portalfiscal.inf.br/nfe'}
        numero = root.find(".//ns:infNFe/ns:ide/ns:nNF", ns).text
        emissor = root.find(".//ns:emit/ns:xNome", ns).text
        destinatario = root.find(".//ns:dest/ns:xNome", ns).text
        valor = float(root.find(".//ns:infNFe/ns:total/ns:ICMSTot/ns:vNF", ns).text)
        data_emissao = root.find(".//ns:infNFe/ns:ide/ns:dhEmi", ns).text[:10]
        
        return {
            "numero": numero,
            "emissor": emissor,
            "destinatario": destinatario,
            "valor": valor,
            "data_emissao": data_emissao
        }
    except Exception as e:
        print(f"Erro ao extrair dados do XML: {e}")
        return None

def capturar_nota(nota):
    """Adiciona a nota fiscal ao banco de dados."""
    try:
        cursor.execute("INSERT INTO notas (numero, emissor, destinatario, valor, data_emissao) VALUES (?, ?, ?, ?, ?)",
                       (nota['numero'], nota['emissor'], nota['destinatario'], nota['valor'], nota['data_emissao']))
        conn.commit()
    except sqlite3.IntegrityError:
        print("Nota fiscal já cadastrada.")

@app.route("/notas/", methods=["GET"])
def listar_notas():
    """Exibe a lista de notas fiscais."""
    cursor.execute("SELECT * FROM notas")
    notas = cursor.fetchall()
    return render_template("notas.html", notas=notas)

@app.route("/notas/acao", methods=["POST"])
def atualizar_status():
    """Atualiza o status da nota fiscal.""" 
    data = request.json
    nota_id = data.get("id")
    status = data.get("status")
    descricao = data.get("descricao", "")
    
    cursor.execute("UPDATE notas SET status=?, descricao=? WHERE id=?", (status, descricao, nota_id))
    conn.commit()
    
    if status == "aprovada":
        cursor.execute("SELECT * FROM notas WHERE id=?", (nota_id,))
        nota = cursor.fetchone()
        nota_formatada = {
            "numero": nota[1], "emissor": nota[2], "destinatario": nota[3], "valor": nota[4], "data_emissao": nota[5]
        }
        enviar_para_api_externa(nota_formatada)
    
    return jsonify({"message": "Status atualizado."})

def enviar_para_api_externa(nota):
    """Envia a nota fiscal aprovada para a API externa."""
    try:
        response = requests.post(API_EXTERNA_URL, json=nota)
        print(f"Resposta da API externa: {response.json()}")
    except Exception as e:
        print(f"Erro ao enviar para API externa: {e}")

def iniciar_monitoramento():
    """Verifica e-mails a cada 30 segundos."""
    while True:
        verificar_emails()
        time.sleep(30)

if __name__ == "__main__":
    threading.Thread(target=iniciar_monitoramento, daemon=True).start()
    app.run(debug=True)
