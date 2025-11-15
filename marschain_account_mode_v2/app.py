import argparse #hdhdh
import json
import os
import threading
from typing import List, Optional, Dict, Any

import requests
from flask import Flask, render_template, request, jsonify, redirect, url_for, session

from blockchain import (
    MarsChain, Transaction, TARGET_BLOCK_TIME, RETARGET_INTERVAL,
    serialize_block, deserialize_block
)
from wallet_ecdsa import generate_seed, wallet_from_seed, sign_message
from db import (
    init_db, create_user, get_user_by_username, get_user_by_id,
    decrypt_seed, verify_password
)

app = Flask(__name__)
app.secret_key = os.environ.get("MARSCHAIN_FLASK_SECRET", "dev-flask-secret-change-me")

init_db()
chain = MarsChain()

PEERS: List[str] = []
NODE_PORT = 5000

def load_peers():
    global PEERS
    env = os.environ.get("MARSCHAIN_PEERS", "")
    if env:
        PEERS = [p.strip() for p in env.split(",") if p.strip()]
    else:
        PEERS = []

def broadcast(path: str, payload: dict):
    def _send():
        for base in PEERS:
            url = base.rstrip("/") + path
            try:
                requests.post(url, json=payload, timeout=2)
            except Exception:
                continue
    threading.Thread(target=_send, daemon=True).start()

def get_current_user() -> Optional[Dict[str, Any]]:
    uid = session.get("user_id")
    if not uid:
        return None
    row = get_user_by_id(int(uid))
    if not row:
        return None
    user_id, username, enc_seed = row
    seed = decrypt_seed(enc_seed)
    norm, priv_hex, pub_hex, addr = wallet_from_seed(seed)
    return {
        "id": user_id,
        "username": username,
        "seed": seed,
        "address": addr,
        "priv_hex": priv_hex,
        "pub_hex": pub_hex,
    }

@app.context_processor
def inject_globals():
    return {"app_name": "MarsChain", "current_user": get_current_user()}

@app.route("/")
def index():
    last_block = chain.last_block
    info = {
        "height": last_block.height,
        "last_hash": last_block.hash(),
        "num_blocks": len(chain.chain),
        "num_txs_mempool": len(chain.mempool),
        "retarget_interval": RETARGET_INTERVAL,
        "port": NODE_PORT,
        "num_peers": len(PEERS),
    }
    return render_template("index.html", title="Dashboard", info=info)

# ---------- Auth ----------

@app.route("/login", methods=["GET", "POST"])
def login():
    message = None
    created_seed = None
    mode = request.form.get("mode") if request.method == "POST" else "login"

    if request.method == "POST":
        username = (request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""
        if not username or not password:
            message = "Username dan password wajib diisi."
        else:
            if mode == "register":
                row = get_user_by_username(username)
                if row:
                    message = "Username sudah terpakai, silakan login."
                else:
                    seed = generate_seed()
                    user_id = create_user(username, password, seed)
                    session["user_id"] = user_id
                    return render_template(
                        "login_success_seed.html",
                        title="Your Seed Phrase",
                        seed_phrase=seed,
                        username=username,
                    )
            else:
                row = get_user_by_username(username)
                if not row:
                    message = "Akun tidak ditemukan, silakan register."
                else:
                    user_id, uname, pw_hash, enc_seed = row
                    if not verify_password(pw_hash, password):
                        message = "Password salah."
                    else:
                        session["user_id"] = user_id
                        return redirect(url_for("wallet_page"))

    return render_template("login.html", title="Login", message=message, active_mode=mode)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ---------- Wallet ----------

@app.route("/wallet", methods=["GET", "POST"])
def wallet_page():
    current = get_current_user()
    manual_created = None
    manual_restored = None
    message = None

    if request.method == "POST" and request.form.get("mode") == "manual":
        action = request.form.get("action")
        if action == "create":
            seed = generate_seed()
            norm, priv, pub, addr = wallet_from_seed(seed)
            manual_created = {
                "seed": norm,
                "private_key": priv,
                "public_key": pub,
                "address": addr,
            }
        elif action == "restore":
            seed_input = request.form.get("seed_phrase", "")
            if not seed_input.strip():
                message = "Seed phrase tidak boleh kosong."
            else:
                norm, priv, pub, addr = wallet_from_seed(seed_input)
                manual_restored = {
                    "seed": norm,
                    "private_key": priv,
                    "public_key": pub,
                    "address": addr,
                }

    addr_query = request.args.get("address")
    balance = None
    if addr_query:
        balance = chain.get_balance(addr_query)

    logged_balance = None
    if current:
        logged_balance = chain.get_balance(current["address"])

    return render_template(
        "wallet.html",
        title="Wallet",
        current=current,
        manual_created=manual_created,
        manual_restored=manual_restored,
        message=message,
        query_address=addr_query,
        query_balance=balance,
        logged_balance=logged_balance,
    )

# ---------- Send ----------

@app.route("/send", methods=["GET", "POST"])
def send_page():
    current = get_current_user()
    message = None
    status = "neutral"
    from_addr = None

    if request.method == "POST":
        to_address = (request.form.get("to_address") or "").strip()
        amount_str = request.form.get("amount") or "0"
        fee_str = request.form.get("fee") or "0"

        try:
            amount = float(amount_str)
            fee = float(fee_str)
        except ValueError:
            message = "Amount / fee tidak valid."
            status = "error"
            return render_template("send.html", title="Send", message=message, status=status, from_addr=None, current=current)

        if not to_address:
            message = "Isi 'to address'."
            status = "error"
            return render_template("send.html", title="Send", message=message, status=status, from_addr=None, current=current)

        if current:
            from_addr = current["address"]
            priv_hex = current["priv_hex"]
            pub_hex = current["pub_hex"]
        else:
            seed_phrase = (request.form.get("seed_phrase") or "").strip()
            if not seed_phrase:
                message = "Seed phrase harus diisi (kalau tidak login)."
                status = "error"
                return render_template("send.html", title="Send", message=message, status=status, from_addr=None, current=current)
            norm, priv_hex, pub_hex, from_addr = wallet_from_seed(seed_phrase)

        tx = Transaction(
            tx_type="TRANSFER",
            from_address=from_addr,
            to_address=to_address,
            asset="MARS",
            amount=amount,
            fee=fee,
            pubkey_hex=pub_hex,
        )
        msg_hash = tx.hash_for_signing()
        sig_hex = sign_message(priv_hex, msg_hash)
        tx.signature_hex = sig_hex

        ok = chain.add_transaction(tx)
        if ok:
            message = f"Transaksi dari {from_addr} ke {to_address} masuk mempool & akan dibroadcast."
            status = "success"
            broadcast("/api/tx/receive", {"tx": tx.to_dict()})
        else:
            message = "Gagal menambahkan transaksi. Cek saldo / signature."
            status = "error"

    return render_template("send.html", title="Send", message=message, status=status, from_addr=from_addr, current=current)

# ---------- Mining ----------

@app.route("/mine")
def mine_page():
    current = get_current_user()
    logged_address = current["address"] if current else ""
    return render_template(
        "mine.html",
        title="Mining",
        target_block_time=TARGET_BLOCK_TIME,
        retarget_interval=RETARGET_INTERVAL,
        logged_address=logged_address,
        has_logged=bool(current),
    )

@app.route("/api/mine_step", methods=["POST"])
def api_mine_step():
    data = request.get_json(force=True)
    miner_address = (data.get("miner_address") or "").strip()
    if not miner_address:
        return jsonify({"ok": False, "error": "Miner address kosong."}), 400

    max_tries = int(data.get("max_tries", 50000))
    block, hashes = chain.mine_block_step(miner_address, max_tries=max_tries)
    resp = {
        "ok": True,
        "hashes": hashes,
        "found": block is not None,
        "last_height": chain.last_block.height,
    }
    if block is not None:
        resp["block"] = {
            "height": block.height,
            "hash": block.hash(),
            "reward": block.transactions[0].amount if block.transactions else 0.0,
        }
        broadcast("/api/block/receive", {"block": serialize_block(block)})
    return jsonify(resp)

# ---------- P2P API ----------

@app.route("/api/tx/receive", methods=["POST"])
def api_tx_receive():
    data = request.get_json(force=True)
    d = data.get("tx")
    if not d:
        return jsonify({"ok": False}), 400
    tx = Transaction(
        tx_type=d.get("tx_type", "TRANSFER"),
        from_address=d.get("from_address"),
        to_address=d.get("to_address"),
        asset=d.get("asset", "MARS"),
        amount=d.get("amount", 0.0),
        fee=d.get("fee", 0.0),
        pubkey_hex=d.get("pubkey_hex"),
        signature_hex=d.get("signature_hex"),
        meta=d.get("meta", {}),
    )
    chain.add_transaction(tx)
    return jsonify({"ok": True})

@app.route("/api/block/receive", methods=["POST"])
def api_block_receive():
    data = request.get_json(force=True)
    b = data.get("block")
    if not b:
        return jsonify({"ok": False}), 400
    block = deserialize_block(b)
    last = chain.last_block

    if block.height == last.height + 1 and block.prev_hash == last.hash():
        if int(block.hash(), 16) >= block.target:
            return jsonify({"ok": False, "error": "invalid pow"}), 400

        tmp_chain = MarsChain()
        tmp_chain.chain = chain.chain.copy()
        tmp_chain._recompute_state()
        for tx in block.transactions:
            if not tmp_chain._apply_tx_to_state(tx, check_sig=True, check_balance=True):
                return jsonify({"ok": False, "error": "invalid tx"}), 400

        chain.chain.append(block)
        chain._recompute_state()
        chain.mempool = []
        chain._save_chain()
        return jsonify({"ok": True})

    return jsonify({"ok": False, "error": "height/prev mismatch"}), 400

# ---------- Explorer & Peers ----------

@app.route("/explorer")
def explorer_page():
    blocks = []
    for b in reversed(chain.chain[-30:]):
        blocks.append({
            "height": b.height,
            "hash": b.hash(),
            "prev_hash": b.prev_hash,
            "num_txs": len(b.transactions),
            "timestamp": b.timestamp,
            "target": str(b.target),
        })
    return render_template("explorer.html", title="Explorer", blocks=blocks)

@app.route("/peers")
def peers_page():
    return render_template("peers.html", title="Peers", peers=PEERS, port=NODE_PORT)

@app.route("/api/peers")
def api_peers():
    return jsonify({"peers": PEERS, "port": NODE_PORT})

def main():
    global NODE_PORT
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    NODE_PORT = args.port
    load_peers()
    app.run(port=NODE_PORT, debug=True)

if __name__ == "__main__":
    main()
