"""
activation_server.py — Servidor de ativação (first-come, first-locked)

Guarda, para cada license_key, o fingerprint do PRIMEIRO dispositivo que
tentou ativá-la. Qualquer dispositivo diferente que tentar usar a mesma
license_key depois é recusado.

Rodar localmente para testar:
    pip install flask
    python activation_server.py
    (sobe em http://localhost:5000)

Para produção, hospede em qualquer serviço que rode Flask/WSGI (um VPS,
Render, Fly.io, PythonAnywhere etc.) e troque a APP_SECRET abaixo por um
valor seu, mantendo o mesmo valor no installer_app.py.

IMPORTANTE: isso é uma defesa básica, não um sistema de licenciamento
comercial robusto. Não guarda nada além do fingerprint — não colete mais
dados do que o necessário.
"""

import sqlite3
import time
from flask import Flask, request, jsonify

app = Flask(__name__)
DB_PATH = "activation.db"

# Mesmo valor precisa estar em installer_app.py (ACTIVATION_SECRET).
# Isso não é segurança forte (pode ser extraído do binário), só filtra
# tentativas aleatórias de bater na API.
APP_SECRET = "troque-isso-para-um-valor-seu"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS licenses (
            license_key TEXT PRIMARY KEY,
            fingerprint TEXT NOT NULL,
            activated_at REAL NOT NULL
        )"""
    )
    return conn


@app.route("/activate", methods=["POST"])
def activate():
    if request.headers.get("X-App-Secret") != APP_SECRET:
        return jsonify({"allowed": False, "reason": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    license_key = data.get("license_key")
    fingerprint = data.get("fingerprint")

    if not license_key or not fingerprint:
        return jsonify({"allowed": False, "reason": "missing_fields"}), 400

    conn = get_db()
    try:
        row = conn.execute(
            "SELECT fingerprint FROM licenses WHERE license_key = ?", (license_key,)
        ).fetchone()

        if row is None:
            conn.execute(
                "INSERT INTO licenses (license_key, fingerprint, activated_at) VALUES (?, ?, ?)",
                (license_key, fingerprint, time.time()),
            )
            conn.commit()
            return jsonify({"allowed": True, "reason": "activated_now"})

        stored_fingerprint = row[0]
        if stored_fingerprint == fingerprint:
            return jsonify({"allowed": True, "reason": "already_activated_same_device"})

        return jsonify({"allowed": False, "reason": "license_bound_to_another_device"})
    finally:
        conn.close()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
