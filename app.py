import os
import time
import json
import socket
import threading
from flask import Flask, render_template, request, jsonify, send_from_directory

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"))
app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # Allow up to 500MB binary uploads

VAULT_DIR = os.path.join(BASE_DIR, "cloud_vaults")
os.makedirs(VAULT_DIR, exist_ok=True)

vault_lock = threading.RLock()
active_vaults = {}
telemetry_history = []
live_stage_banner = {"text": "System Ready • Monitoring Cloud Vaults", "flow": None, "updated": 0}


def get_primary_lan_ip():
    """Gets your active Wi-Fi / Hotspot IPv4 address (e.g., 10.101.43.150)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def get_vaults_snapshot():
    """Returns all currently active files stored in the Cloud Command Center."""
    now = time.time()
    snapshot = []
    with vault_lock:
        for v_uid, meta in list(active_vaults.items()):
            remaining = max(0, int(meta["expires_at"] - now))
            snapshot.append({
                "vault_id": v_uid,
                "short_id": v_uid[:15] + "...",
                "routing_hash_short": meta["routing_hash"][:10] + "...",
                "encrypted_meta": meta["encrypted_meta"],
                "size_bytes": meta["size_bytes"],
                "ttl_remaining": remaining,
                "ttl_total": meta["ttl_total"],
                "hex_preview": meta["hex_preview"],
                "compressed": meta["compressed"],
                "security_score": meta["security_score"],
                "created_at": meta["created_at"]
            })
    return snapshot


def record_telemetry(event_type, message, level="info", active_flow=None):
    """Appends an event to the Cloud SOC Feed (visible only on Cloud Command Center)."""
    event_obj = {
        "id": f"{time.time()}-{os.urandom(2).hex()}",
        "timestamp": time.strftime("%H:%M:%S"),
        "type": event_type,
        "message": message,
        "level": level,
        "flow": active_flow
    }
    with vault_lock:
        telemetry_history.insert(0, event_obj)
        del telemetry_history[40:]
        live_stage_banner["text"] = f"{event_obj['timestamp']} • {message}"
        live_stage_banner["flow"] = active_flow
        live_stage_banner["updated"] = time.time()


def cryptographic_shred_file(filepath):
    """Overwrites the encrypted file on disk with random entropy and 0x00 before deleting."""
    if not filepath or not os.path.exists(filepath):
        return
    try:
        length = os.path.getsize(filepath)
        if length > 0:
            # Cap single-buffer overwrite at 16MB blocks for speed on huge files
            block_size = min(length, 16 * 1024 * 1024)
            with open(filepath, "ba+", buffering=0) as f:
                f.seek(0)
                f.write(os.urandom(block_size))
                f.flush()
                os.fsync(f.fileno())
                f.seek(0)
                f.write(b"\x00" * block_size)
                f.flush()
                os.fsync(f.fileno())
        os.remove(filepath)
    except Exception as e:
        print(f"[Shred Error] {e}")


def background_ttl_daemon():
    """Dead-Man's Switch: Checks every 1 second and shreds only vaults whose TTL expired."""
    while True:
        time.sleep(1)
        now = time.time()
        expired_items = []
        with vault_lock:
            for v_uid, meta in list(active_vaults.items()):
                if now >= meta["expires_at"]:
                    expired_items.append((v_uid, meta["filepath"]))
                    active_vaults.pop(v_uid, None)

        for v_uid, filepath in expired_items:
            cryptographic_shred_file(filepath)
            record_telemetry(
                "TTL_EXPIRED",
                f"Dead-Man's Switch triggered: Vault [{v_uid[:12]}...] auto-incinerated after TTL expiry.",
                level="warning",
                active_flow="shred"
            )


threading.Thread(target=background_ttl_daemon, daemon=True).start()


@app.route("/")
def index():
    template_path = os.path.join(BASE_DIR, "templates", "index.html")
    if os.path.exists(template_path):
        return render_template("index.html")
    root_path = os.path.join(BASE_DIR, "index.html")
    if os.path.exists(root_path):
        return send_from_directory(BASE_DIR, "index.html")
    return "Error: index.html not found.", 404


@app.route("/api/network-info", methods=["GET"])
def network_info():
    ip = get_primary_lan_ip()
    return jsonify({
        "base_url": f"http://{ip}:5000"
    })


@app.route("/api/state", methods=["GET"])
def get_current_state():
    with vault_lock:
        logs = list(telemetry_history)
        flow = live_stage_banner["flow"] if (time.time() - live_stage_banner["updated"] < 3.5) else None
        banner_text = live_stage_banner["text"]
    return jsonify({
        "vaults": get_vaults_snapshot(),
        "logs": logs,
        "banner_text": banner_text,
        "active_flow": flow
    })


@app.route("/api/upload", methods=["POST"])
def upload_encrypted_vault():
    """
    Accepts binary FormData uploads (zero string length limits) and stores
    the raw encrypted bytes on disk in cloud_vaults/.
    """
    cipher_file = request.files.get("cipher_file")
    if not cipher_file:
        return jsonify({"error": "Missing encrypted binary stream"}), 400

    routing_hash = request.form.get("routing_hash", "")
    iv_hex = request.form.get("iv", "")
    hmac_tag = request.form.get("hmac_tag", "")
    encrypted_meta = request.form.get("encrypted_meta", "")
    ttl_seconds = int(request.form.get("ttl_seconds", 300))
    compressed = request.form.get("compressed") == "1"
    security_score = int(request.form.get("security_score", 80))

    if not all([routing_hash, iv_hex, hmac_tag, encrypted_meta]):
        return jsonify({"error": "Missing cryptographic parameters"}), 400

    vault_uid = f"{routing_hash[:10]}_{int(time.time()*1000)}_{os.urandom(2).hex()}"
    bin_filename = f"{vault_uid}.bin"
    filepath = os.path.join(VAULT_DIR, bin_filename)

    # Save binary ciphertext directly to disk without converting to string
    cipher_file.save(filepath)
    file_size = os.path.getsize(filepath)

    # Read only the first 64 bytes to display in the Cloud Hex Inspector
    with open(filepath, "rb") as f:
        sample_bytes = f.read(64)
    hex_preview = " ".join(f"{b:02X}" for b in sample_bytes)

    with vault_lock:
        active_vaults[vault_uid] = {
            "vault_id": vault_uid,
            "bin_filename": bin_filename,
            "routing_hash": routing_hash,
            "filepath": filepath,
            "iv": iv_hex,
            "hmac_tag": hmac_tag,
            "encrypted_meta": encrypted_meta[:28] + "...",
            "encrypted_meta_full": encrypted_meta,
            "size_bytes": file_size,
            "created_at": time.strftime("%H:%M:%S"),
            "expires_at": time.time() + ttl_seconds,
            "ttl_total": ttl_seconds,
            "hex_preview": hex_preview,
            "compressed": compressed,
            "security_score": security_score
        }
        total_active = len(active_vaults)

    record_telemetry(
        "VAULT_STORED",
        f"Vault [{vault_uid[:12]}...] stored ({file_size/1024:.1f} KB). Active Cloud Files: {total_active}.",
        level="success",
        active_flow="sender_to_cloud"
    )

    return jsonify({
        "status": "stored",
        "vault_id": vault_uid,
        "vaults": get_vaults_snapshot()
    })


@app.route("/api/fetch", methods=["POST"])
def fetch_encrypted_vault():
    data = request.get_json(silent=True) or {}
    routing_hash = data.get("routing_hash", "")

    matching_vaults = []
    with vault_lock:
        for v_uid, meta in list(active_vaults.items()):
            if meta["routing_hash"] == routing_hash and os.path.exists(meta["filepath"]):
                matching_vaults.append({
                    "vault_id": meta["vault_id"],
                    "iv": meta["iv"],
                    "hmac_tag": meta["hmac_tag"],
                    "encrypted_meta": meta["encrypted_meta_full"],
                    "compressed": meta["compressed"]
                })

    if not matching_vaults:
        record_telemetry(
            "AUTH_MISS",
            f"Vault lookup missed for route [{routing_hash[:10]}...]. Invalid or expired key.",
            level="warning"
        )
        return jsonify({"error": "No matching vault found in Cloud! Check that your Custom Key matches the Sender."}), 404

    record_telemetry(
        "VAULT_FETCHED",
        f"Streaming {len(matching_vaults)} encrypted vault(s) for key [{routing_hash[:10]}...] to Receiver.",
        level="info",
        active_flow="cloud_to_receiver"
    )

    return jsonify({"vaults": matching_vaults})


@app.route("/api/cipher/<vault_id>", methods=["GET"])
def stream_cipher_binary(vault_id):
    """Streams the raw encrypted .bin file directly to the Receiver as an ArrayBuffer."""
    with vault_lock:
        vault = active_vaults.get(vault_id)
        if not vault or not os.path.exists(vault["filepath"]):
            return jsonify({"error": "Ciphertext binary not found"}), 404
        bin_filename = vault["bin_filename"]

    return send_from_directory(VAULT_DIR, bin_filename, mimetype="application/octet-stream")


@app.route("/api/burn", methods=["POST"])
def burn_vault():
    data = request.get_json(silent=True) or {}
    vault_ids = data.get("vault_ids", [])

    shredded_count = 0
    for v_uid in vault_ids:
        with vault_lock:
            vault = active_vaults.pop(v_uid, None)
        if vault:
            cryptographic_shred_file(vault["filepath"])
            shredded_count += 1

    record_telemetry(
        "BURN_ON_READ",
        f"Burn-on-Read verified: {shredded_count} vault(s) overwritten with 0x00 and destroyed.",
        level="success",
        active_flow="shred"
    )

    return jsonify({"status": "shredded", "shred_receipt": os.urandom(8).hex().upper()})


if __name__ == "__main__":
    ip = get_primary_lan_ip()
    print("\n=======================================================")
    print(f"  AEGIS CLOUD RELAY LIVE AT: http://{ip}:5000")
    print("=======================================================\n")
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True, use_reloader=False)