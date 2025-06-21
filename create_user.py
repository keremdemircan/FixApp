import sqlite3

DB_FILE = "users.db"

username = input("Kullanıcı adı: ")
password = input("Şifre: ")

conn = sqlite3.connect(DB_FILE)
c = conn.cursor()
c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
conn.commit()
conn.close()
print("Kullanıcı eklendi!")
