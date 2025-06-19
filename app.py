from flask import Flask, render_template, request, redirect
import subprocess
import datetime
import os

app = Flask(__name__)

DATA_FILE = "assets.txt"

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        asset = request.form.get("asset")
        asset_type = request.form.get("type")
        editor = request.form.get("editor")
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(DATA_FILE, "a") as f:
            f.write(f"{asset},{asset_type},{editor},{now}\n")
        return redirect("/")
    # Kayıtları oku
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE) as f:
            rows = [line.strip().split(",") for line in f.readlines()]
    else:
        rows = []
    return render_template("index.html", rows=rows)

@app.route("/sync", methods=["POST"])
def sync_git():
    subprocess.run(["git", "add", DATA_FILE])
    subprocess.run(["git", "commit", "-m", "Update asset feed"])
    subprocess.run(["git", "push"])
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True)
