from flask import Flask, request, jsonify, session, render_template, redirect
import base64
import os
import time
import threading
import sqlite3
import xml.etree.ElementTree as ET
import queue
import requests
import logging
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from groq import Groq

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET")

groq_client = Groq(api_key=os.getenv("GROQ_API_KEY", "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"))

SCOPES = ["https://mail.google.com/"]
TOKEN_PATH = "token.json"
CREDENTIALS_PATH = "credentials.json"
API_EXTERNA_URL = os.getenv("API_EXTERNA_URL", "http://localhost:5001/api/notas/")

# Fila para processar notas
fila_notas = queue.Queue()

# Banco SQLite
conn = sqlite3.connect("notas_fiscais.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS notas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        numero TEXT UNIQUE,
        emissor TEXT,
        destinatario TEXT,
        valor REAL,
        data_emissao TEXT,
        status TEXT DEFAULT 'pendente',
        descricao TEXT
    )""")
conn.commit()

def obter_credenciais():
    creds = None

    # Verifica se já existe um token salvo
    if os.path.exists(TOKEN_PATH):
        creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)

    # Se não há credenciais válidas ou expiraram mas há refresh token, atualiza
    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
        except Exception as e:
            print(f"Erro ao renovar token: {e}")
            creds = None

    # Se não há credenciais válidas, inicia novo fluxo de autenticação
    if not creds or not creds.valid:
        if not os.path.exists(CREDENTIALS_PATH):
            raise FileNotFoundError("credentials.json não encontrado!")
        flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_PATH, SCOPES)
        creds = flow.run_local_server(port=8080)

    # Salva/atualiza o token
    with open(TOKEN_PATH, "w") as f:
        f.write(creds.to_json())

    return creds

def verificar_emails():
    """Captura e-mails e verifica se possuem notas fiscais XML."""
    encontrou_nota = False
    try:
        creds = obter_credenciais()
        service = build("gmail", "v1", credentials=creds)
        results = service.users().messages().list(userId="me", q="is:unread", maxResults=10).execute()
        messages = results.get("messages", [])

        for message in messages:
            msg = service.users().messages().get(userId="me", id=message["id"]).execute()
            tipo, corpo = verificar_corpo_email(msg)

            if tipo == "xml_inline":
                nota = extrair_dados_xml(corpo)
                if nota:
                    capturar_nota(nota)
                    encontrou_nota = True

            elif tipo == "xml_attachment":
                for part in msg.get("payload", {}).get("parts", []):
                    filename = part.get("filename", "")
                    if filename.endswith(".xml"):
                        body_info = part.get("body", {})
                        data = body_info.get("data")
                        if not data and "attachmentId" in body_info:
                            attachment = service.users().messages().attachments().get(
                                userId="me", messageId=msg["id"], id=body_info["attachmentId"]
                            ).execute()
                            data = attachment.get("data")
                        if data:
                            try:
                                xml_content = base64.urlsafe_b64decode(data).decode("utf-8")
                                nota = extrair_dados_xml(xml_content)
                                if nota:
                                    capturar_nota(nota)
                                    encontrou_nota = True
                            except Exception as e:
                                logging.warning(f"Erro ao decodificar XML: {e}")
            elif tipo == "keywords":
                logging.info("Palavras-chave encontradas, mas sem XML.")

            service.users().messages().modify(userId="me", id=message["id"], body={"removeLabelIds": ["UNREAD"]}).execute()

    except Exception as e:
        logging.error(f"Erro ao verificar e-mails: {e}")
    
    return encontrou_nota

def extrair_texto(part):
    if part.get("mimeType", "").startswith("text/"):
        data = part.get("body", {}).get("data")
        if data:
            return base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")
    for sub in part.get("parts", []):
        texto = extrair_texto(sub)
        if texto:
            return texto
    return ""

def verificar_corpo_email(msg):
    body, parts = "", msg.get("payload", {}).get("parts", [])
    for p in parts:
        body += extrair_texto(p) or ""
    if "<NFe" in body:
        return "xml_inline", body
    if any(p.get("filename", "").endswith(".xml") for p in parts):
        return "xml_attachment", None
    return None, None

def extrair_dados_xml(xml_content):
    try:
        ns = {"ns":"http://www.portalfiscal.inf.br/nfe"}
        root = ET.fromstring(xml_content)
        return {
            "numero": root.findtext(".//ns:infNFe/ns:ide/ns:nNF", ns),
            "emissor": root.findtext(".//ns:emit/ns:xNome", ns),
            "destinatario": root.findtext(".//ns:dest/ns:xNome", ns),
            "valor": float(root.findtext(".//ns:ICMSTot/ns:vNF", ns)),
            "data_emissao": root.findtext(".//ns:ide/ns:dhEmi", ns)[:10]
        }
    except Exception as e:
        logging.error("Erro XML: %s", e)
        return None

def polling_emails():
    while True:
        try:
            creds = obter_credenciais()
            service = build("gmail", "v1", credentials=creds)
            msgs = service.users().messages().list(userId="me", q="is:unread", maxResults=10).execute().get("messages", [])
            logging.info("Verificando %d emails", len(msgs))
            for m in msgs:
                msg = service.users().messages().get(userId="me", id=m["id"]).execute()
                tipo, corpo = verificar_corpo_email(msg)
                if tipo == "xml_inline":
                    nota = extrair_dados_xml(corpo)
                    if nota:
                        fila_notas.put(nota)
                elif tipo == "xml_attachment":
                    for p in msg.get("payload", {}).get("parts", []):
                        if p.get("filename","").endswith(".xml"):
                            data = p["body"].get("data") or service.users().messages().attachments().get(
                                userId="me", messageId=m["id"], id=p["body"]["attachmentId"]).execute().get("data")
                            xml = base64.urlsafe_b64decode(data).decode("utf-8")
                            nota = extrair_dados_xml(xml)
                            if nota:
                                fila_notas.put(nota)
                service.users().messages().modify(userId="me", id=m["id"], body={"removeLabelIds":["UNREAD"]}).execute()
        except Exception as e:
            logging.error("Polling falhou: %s", e)
        time.sleep(90)

def worker():
    while True:
        nota = fila_notas.get()
        if not nota:
            continue
        try:
            cursor.execute("""
                INSERT INTO notas(numero, emissor, destinatario, valor, data_emissao)
                VALUES(?,?,?,?,?)""",
                (nota["numero"],nota["emissor"],nota["destinatario"],nota["valor"],nota["data_emissao"])
            )
            conn.commit()
            logging.info("Nota %s salva", nota["numero"])
            enviar_para_api_externa(nota)
        except sqlite3.IntegrityError:
            logging.info("Nota %s já existe", nota["numero"])
        except Exception as e:
            logging.error("Worker erro: %s", e)
        finally:
            fila_notas.task_done()

def capturar_nota(nota):
    try:
        cursor.execute("INSERT INTO notas (numero, emissor, destinatario, valor, data_emissao) VALUES (?, ?, ?, ?, ?)",
                       (nota['numero'], nota['emissor'], nota['destinatario'], nota['valor'], nota['data_emissao']))
        conn.commit()
        logging.info(f"Nota {nota['numero']} salva com sucesso.")
    except sqlite3.IntegrityError:
        logging.info(f"Nota {nota['numero']} já cadastrada.")
    except Exception as e:
        logging.error(f"Erro ao salvar nota: {e}")

def enviar_para_api_externa(nota):
    try:
        resp = requests.post(API_EXTERNA_URL, json=nota)
        logging.info("API externa respondeu: %s", resp.status_code)
    except Exception as e:
        logging.error("Erro API externa: %s", e)

# Configura threads
threading.Thread(target=polling_emails, daemon=True).start()
threading.Thread(target=worker, daemon=True).start()


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

def carregar_banco():
    try:
        conn = sqlite3.connect("notas_fiscais.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, numero, emissor, destinatario, valor, data_emissao, status, descricao FROM notas")
        notas = cursor.fetchall()
        conn.close()
        
        if not notas:
            return "Não há registros de buracos detectados no banco de dados."

        contexto = "Aqui estão os registros de buracos detectados:\n"
        for registro in notas:
            id_, numero, emissor, destinatario, valor, data_emissao, status, descricao = registro

            contexto += (
                f"- ID: {id_}, Nº: {numero}, Emissor: {emissor}, Destinatário: {destinatario}, "
                f"Valor: R${valor:.2f}, Data de Emissão: {data_emissao}, "
                f"Status: {status}, Descrição: {descricao}\n"
            )
        
        return contexto
    except Exception as e:
        return f"Erro ao carregar banco de dados: {str(e)}"

@app.route("/chat", methods=["POST"])
def chat():
    contexto_banco = carregar_banco()
    try:
        dados = request.json
        if not dados or "pergunta" not in dados:
            return jsonify({"erro": "Solicitação inválida. O campo 'pergunta' é obrigatório."}), 400
        
        pergunta = dados["pergunta"]
        
        prompt = f"""
        Você é um assistente de IA especializado em gerenciamento de notas fiscais para uma empresa.
        Sua função é auxiliar o gestor a consultar, autorizar, validar, verificar status e fornecer informações detalhadas sobre as notas fiscais com base nos dados disponíveis do banco de dados.

        **Importante:** Você **NÃO** deve sugerir código ou consultas SQL. Responda apenas com base nos dados fornecidos a você, de forma clara, objetiva e adequada ao contexto empresarial.
        
        {contexto_banco}
        
        Pergunta: {pergunta}
        """
        
        response = groq_client.chat.completions.create(
            model="deepseek-r1-distill-llama-70b",
            messages=[
                {"role": "system", "content": "Você é um assistente de IA especializado em gerenciamento de notas fiscais para uma empresa. NÃO forneça código SQL."},
                {"role": "user", "content": prompt}
            ]
        )
        
        resposta_texto = response.choices[0].message.content.strip() if response.choices else "Não foi possível gerar uma resposta."

        return jsonify({"resposta": resposta_texto})
    except Exception as e:
        return jsonify({"erro": f"Erro interno do servidor: {str(e)}"}), 500


if __name__ == "__main__":
    threading.Thread(target=iniciar_monitoramento, daemon=True).start()
    app.run()
