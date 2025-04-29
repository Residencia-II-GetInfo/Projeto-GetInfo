from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)

# Inicializa o banco de dados
DB_PATH = "notas_recebidas.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notas_recebidas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            numero TEXT UNIQUE,
            emissor TEXT,
            destinatario TEXT,
            valor REAL,
            data_emissao TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route("/api/notas/", methods=["POST"])
def receber_nota():
    data = request.get_json()
    campos_esperados = ["numero", "emissor", "destinatario", "valor", "data_emissao"]

    if not all(campo in data for campo in campos_esperados):
        return jsonify({"error": "Dados incompletos"}), 400

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO notas_recebidas (numero, emissor, destinatario, valor, data_emissao)
            VALUES (?, ?, ?, ?, ?)
        ''', (data["numero"], data["emissor"], data["destinatario"], data["valor"], data["data_emissao"]))
        conn.commit()
        conn.close()
        return jsonify({"message": "Nota recebida com sucesso"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Nota já cadastrada"}), 409
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/notas/", methods=["GET"])
def listar_notas_recebidas():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM notas_recebidas")
    notas = cursor.fetchall()
    conn.close()
    return jsonify([
        {
            "id": nota[0],
            "numero": nota[1],
            "emissor": nota[2],
            "destinatario": nota[3],
            "valor": nota[4],
            "data_emissao": nota[5]
        } for nota in notas
    ])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
