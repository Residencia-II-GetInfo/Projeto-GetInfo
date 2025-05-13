# 📄 Projeto GetInfo - Sistema de Notas Fiscais

O **Projeto GetInfo** é uma aplicação web desenvolvida no contexto da **Residência II - GetInfo**, com o objetivo de gerenciar notas fiscais eletrônicas (NF-e). O sistema permite o recebimento, validação e aprovação das notas fiscais antes de seu armazenamento definitivo no banco de dados.

---

## 🚀 Funcionalidades

- 📥 **Recebimento de NF-e:** Permite o envio/upload de notas fiscais.
- ⏳ **Aprovação manual ou automatizada:** As notas aguardam verificação antes de serem validadas.
- 💾 **Persistência em banco de dados:** Após a aprovação, a nota é salva de forma segura.
- 🖥️ **Interface web simples e funcional.**

---

## 🛠 Tecnologias Utilizadas

- Python com Flask  
- HTML / CSS / JavaScript  
- SQLite ou outro banco relacional
- Bootstrap

---

## ⚙️ Como Executar

```bash
# Clone o repositório
git clone https://github.com/Residencia-II-GetInfo/Projeto-GetInfo.git
cd Projeto-GetInfo

# Crie e ative um ambiente virtual
python -m venv venv
source venv/bin/activate  # ou venv\Scripts\activate no Windows

# Instale as dependências
pip install -r requirements.txt

# Execute o servidor
python app.py
