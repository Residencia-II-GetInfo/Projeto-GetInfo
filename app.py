from flask import Flask, request, jsonify, render_template, redirect, session
import base64
import os
import re
import time
import threading
import requests
import sqlite3
import xml.etree.ElementTree as ET
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

app = Flask(__name__)
app.secret_key = "cf9a697f72e1d2c1fadcdfc49b4a6818ee80c8c8c5d5d8d5cdee3c4b1fe68bb2"


# Configuração da API do Gmail
SCOPES = ["https://mail.google.com/"]
TOKEN_PATH = "token.json"
CREDENTIALS_PATH = "credentials.json"
API_EXTERNA_URL = "http://localhost:5001/api/notas/"

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

def obter_credenciais():
    """Obtém as credenciais do usuário, gerando token.json se necessário."""
    creds = None
    if os.path.exists(TOKEN_PATH):
        creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
    else:
        if not os.path.exists(CREDENTIALS_PATH):
            raise FileNotFoundError("credentials.json não encontrado!")
        flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_PATH, SCOPES)
        creds = flow.run_local_server(port=8081)
        with open(TOKEN_PATH, "w") as token:
            token.write(creds.to_json())
    return creds


def verificar_emails():
    """Captura e-mails e verifica se possuem notas fiscais XML ou palavras-chave no corpo."""
    encontrou_nota = False
    try:
        creds = obter_credenciais()
        service = build("gmail", "v1", credentials=creds)
        results = service.users().messages().list(userId="me", q="is:unread", maxResults=10).execute()
        messages = results.get("messages", [])
        
        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            
            if verificar_corpo_email(msg):
                for part in msg.get("payload", {}).get("parts", []):
                    if part.get("filename", "").endswith(".xml"):
                        data = part.get("body", {}).get("data")
                        if data:
                            xml_content = base64.urlsafe_b64decode(data).decode("utf-8")
                            nota = extrair_dados_xml(xml_content)
                            if nota:
                                capturar_nota(nota)
                                encontrou_nota = True
                
                service.users().messages().modify(userId="me", id=message["id"], body={"removeLabelIds": ["UNREAD"]}).execute()
    except Exception as e:
        print(f"[ERRO] Falha ao verificar e-mails: {e}")
    
    return encontrou_nota


def verificar_corpo_email(msg):
    """Verifica se há anexo XML ou palavras-chave no corpo do e-mail (robusto)."""
    body = ""
    has_xml = False

    payload = msg.get("payload", {})
    parts = payload.get("parts", [])

    # Se tiver múltiplas partes (com anexos ou HTML/text)
    for part in parts:
        filename = part.get("filename", "")
        if filename.endswith(".xml"):
            has_xml = True
        if part.get("mimeType") == "text/plain" and "data" in part.get("body", {}):
            body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")

    # Se não tiver parts (e-mail simples), tente direto
    if not parts and payload.get("mimeType") == "text/plain":
        if "data" in payload.get("body", {}):
            body = base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8")

    palavras_chave = ["nota fiscal", "nfe", "número da nota", "imposto", "nota eletrônica"]

    if has_xml:
        print("E-mail contém anexo XML. Provável nota fiscal.")
        return True
    elif any(p in body.lower() for p in palavras_chave):
        print("Corpo do e-mail indica uma nota fiscal.")
        return True
    else:
        print("E-mail não contém indícios de nota fiscal.")
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
    try:
        print("Tentando salvar nota:", nota)  # ADICIONE
        cursor.execute("INSERT INTO notas (numero, emissor, destinatario, valor, data_emissao) VALUES (?, ?, ?, ?, ?)",
                       (nota['numero'], nota['emissor'], nota['destinatario'], nota['valor'], nota['data_emissao']))
        conn.commit()
        print("Nota salva com sucesso!")  # ADICIONE
    except sqlite3.IntegrityError:
        print("Nota fiscal já cadastrada.")
    except Exception as e:
        print("Erro ao salvar nota:", e)

def enviar_para_api_externa(nota):
    try:
        response = requests.post(API_EXTERNA_URL, json=nota)
        print(f"Resposta da API externa: {response.json()}")
    except Exception as e:
        print(f"Erro ao enviar para API externa: {e}")

@app.route("/")
def login():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def autenticar():
    if request.form['username'] == 'admin' and request.form['password'] == '1234':
        session['logado'] = True
        return redirect("/dashboard")
    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/dashboard")
def dashboard():
    if not session.get('logado'):
        return redirect("/")
    cursor.execute("SELECT * FROM notas")
    notas = cursor.fetchall()
    return render_template("dashboard.html", notas=notas)

@app.route("/notas/acao", methods=["POST"])
def atualizar_status():
    if not session.get('logado'):
        return jsonify({"error": "Não autorizado."}), 401
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
    """Verifica e-mails a cada 90 segundos se não houver nota."""
    while True:
        print("\n⏳ Verificando e-mails...")
        houve_resultado = verificar_emails()
        if not houve_resultado:
            print("🕒 Nenhuma nota fiscal encontrada. Aguardando...")
        time.sleep(90)


if __name__ == "__main__":
    threading.Thread(target=iniciar_monitoramento, daemon=True).start()
    app.run()
