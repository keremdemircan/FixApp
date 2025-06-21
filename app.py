from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import subprocess
import datetime
import os
import re
import json
import xml.etree.ElementTree as ET

app = Flask(__name__)
app.secret_key = "kerem_secret"

DB_FILE = "users.db"
RECORDS_FILE = "Records/records.txt"
TYPES = {
    "IP":     {"txt": "IP/IPs.txt",     "json": "IP/IPs.json",     "xml": "IP/IPs.xml"},
    "DOMAIN": {"txt": "Domain/Domains.txt", "json": "Domain/Domains.json", "xml": "Domain/Domains.xml"},
    "HASH":   {"txt": "Hash/Hashes.txt",  "json": "Hash/Hashes.json",  "xml": "Hash/Hashes.xml"},
    "URL":    {"txt": "URL/URLs.txt",    "json": "URL/URLs.json",    "xml": "URL/URLs.xml"},
}

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )''')
    conn.commit()
    conn.close()

init_db()

def read_records():
    if not os.path.exists(RECORDS_FILE):
        return []
    with open(RECORDS_FILE, "r", encoding="utf-8") as f:
        rows = [line.strip().split(",") for line in f if line.strip()]
    return rows

def add_record(asset, asset_type, editor, date):
    txt_file = TYPES[asset_type]["txt"]
    with open(txt_file, "a", encoding="utf-8") as f:
        f.write(f"{asset}\n")
    json_file = TYPES[asset_type]["json"]
    _append_json(json_file, {"asset": asset, "type": asset_type, "editor": editor, "date": date})
    xml_file = TYPES[asset_type]["xml"]
    _append_xml(xml_file, {"asset": asset, "type": asset_type, "editor": editor, "date": date})

def _append_json(filename, entry):
    data = []
    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except:
                data = []
    data.append(entry)
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def _append_xml(filename, entry):
    if os.path.exists(filename):
        tree = ET.parse(filename)
        root = tree.getroot()
    else:
        root = ET.Element("assets")
    asset_elem = ET.SubElement(root, "asset")
    for k, v in entry.items():
        child = ET.SubElement(asset_elem, k)
        child.text = v
    tree = ET.ElementTree(root)
    tree.write(filename, encoding="utf-8", xml_declaration=True)

def add_to_records(asset, asset_type, editor, date):
    with open(RECORDS_FILE, "a", encoding="utf-8") as f:
        f.write(f"{asset},{asset_type},{editor},{date}\n")

def extract_display_name(email):
    if not email or '@' not in email or '.' not in email.split('@')[0]:
        return email
    namepart = email.split('@')[0]
    if '.' in namepart:
        firstname, lastname = namepart.split('.', 1)
        return f"{firstname.capitalize()} {lastname.capitalize()}"
    else:
        return namepart.capitalize()

def is_valid_ip(ip):
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if not re.match(pattern, ip):
        return False
    nums = ip.split(".")
    return all(0 <= int(n) <= 255 for n in nums)

def is_valid_domain(domain):
    pattern = r"^(?!\-)([a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,}$"
    return re.match(pattern, domain) is not None

def is_valid_url(url):
    pattern = r"^(http|https)://[^\s]+$"
    return re.match(pattern, url) is not None

def is_valid_hash(hashval):
    return (
        (len(hashval)==32  and re.fullmatch(r"[a-fA-F0-9]{32}",  hashval)) or
        (len(hashval)==40  and re.fullmatch(r"[a-fA-F0-9]{40}",  hashval)) or
        (len(hashval)==64  and re.fullmatch(r"[a-fA-F0-9]{64}",  hashval))
    )

def asset_exists(asset, asset_type):
    if not os.path.exists(RECORDS_FILE):
        return False
    with open(RECORDS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            parts = line.strip().split(",")
            if len(parts) < 2:
                continue
            existing_asset, existing_type = parts[0].strip(), parts[1].strip()
            if existing_asset == asset and existing_type == asset_type:
                return True
    return False

def delete_assets(assets_with_types):
    # assets_with_types: [("asset", "type")]
    # 1. records.txt güncelle
    new_records = []
    deleted = set()
    if os.path.exists(RECORDS_FILE):
        with open(RECORDS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) < 2:
                    continue
                asset, asset_type = parts[0].strip(), parts[1].strip()
                if (asset, asset_type) in assets_with_types:
                    deleted.add((asset, asset_type))
                    continue
                new_records.append(line)
        with open(RECORDS_FILE, "w", encoding="utf-8") as f:
            for line in new_records:
                f.write(line.strip() + "\n")
    # 2. asset type dosyaları güncelle
    for asset, asset_type in assets_with_types:
        # TXT dosyası
        txt_file = TYPES[asset_type]["txt"]
        if os.path.exists(txt_file):
            with open(txt_file, "r", encoding="utf-8") as f:
                lines = [l for l in f if l.strip() != asset]
            with open(txt_file, "w", encoding="utf-8") as f:
                for l in lines:
                    f.write(l.strip() + "\n")
        # JSON dosyası
        json_file = TYPES[asset_type]["json"]
        if os.path.exists(json_file):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                data = [row for row in data if row.get("asset") != asset]
                with open(json_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
            except:
                pass
        # XML dosyası
        xml_file = TYPES[asset_type]["xml"]
        if os.path.exists(xml_file):
            try:
                tree = ET.parse(xml_file)
                root = tree.getroot()
                for elem in list(root.findall("asset")):
                    elem_asset = elem.find("asset")
                    if elem_asset is not None and elem_asset.text == asset:
                        root.remove(elem)
                tree.write(xml_file, encoding="utf-8", xml_declaration=True)
            except:
                pass

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            session["user"] = username
            flash("Giriş başarılı!", "success")
            return redirect(url_for("index"))
        else:
            flash("Kullanıcı adı veya şifre hatalı.", "danger")
            return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Çıkış yapıldı.", "success")
    return redirect(url_for("login"))

@app.route("/", methods=["GET", "POST"])
def index():
    if "user" not in session:
        return redirect(url_for("login"))

    display_name = extract_display_name(session["user"])

    if request.method == "POST":
        # Silme isteği mi?
        if "delete_selected" in request.form:
            selected = request.form.getlist("selected_asset")
            if selected:
                parsed = [tuple(s.split("|||")) for s in selected]
                delete_assets(parsed)
                flash(f"{len(parsed)} asset silindi.", "success")
            else:
                flash("Hiçbir asset seçilmedi.", "danger")
            return redirect(url_for("index"))

        # Ekleme işlemi
        assets_input = request.form.get("asset")
        asset_type = request.form.get("type")
        editor = display_name
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        asset_list = [a.strip() for a in assets_input.split(";") if a.strip()]

        invalid_assets = []
        exists_assets = []
        added_assets = []

        for asset in asset_list:
            if asset_type == "IP":
                valid = is_valid_ip(asset)
                err = "Geçersiz IP formatı!"
            elif asset_type == "DOMAIN":
                valid = is_valid_domain(asset)
                err = "Geçersiz domain formatı!"
            elif asset_type == "URL":
                valid = is_valid_url(asset)
                err = "Geçersiz URL formatı!"
            elif asset_type == "HASH":
                valid = is_valid_hash(asset)
                err = "Geçersiz hash formatı!"
            else:
                valid = False
                err = "Bilinmeyen tür!"
            if not valid:
                invalid_assets.append(f"{asset} ({err})")
                continue
            if asset_exists(asset, asset_type):
                exists_assets.append(asset)
                continue
            add_record(asset, asset_type, editor, now)
            add_to_records(asset, asset_type, editor, now)
            added_assets.append(asset)

        if added_assets:
            flash(f"{'; '.join(added_assets)} ekleme başarılı.", "success")
        if exists_assets:
            flash(f"{', '.join(exists_assets)} sistemde kayıtlı olduğu için eklenemedi.", "danger")
        if invalid_assets:
            flash(f"{', '.join(invalid_assets)} formatı hatalı olduğu için eklenemedi.", "danger")

        return redirect(url_for("index"))

    rows = read_records()[::-1]
    return render_template("index.html", rows=rows, username=display_name)

def sync_git():
    try:
        subprocess.run(["git", "add", "."], check=True)
        subprocess.run(["git", "commit", "-m", "Update asset files"], check=True)
        subprocess.run(["git", "push"], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print("Git sync failed:", e)
        return False

@app.route("/sync", methods=["POST"])
def sync():
    if "user" not in session:
        return redirect(url_for("login"))
    if sync_git():
        flash("Git sync başarılı!", "success")
    else:
        flash("Git sync başarısız!", "danger")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
