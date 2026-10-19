"""Deliberately vulnerable demo app. FOR LOCAL SECURITY TESTING ONLY."""
import os
import sqlite3
import subprocess

from flask import Flask, request, render_template_string, session, redirect

app = Flask(__name__)
app.secret_key = "insecure-secret"  # VULN: hardcoded secret
DB = "/tmp/vuln.db"
FILES_DIR = os.path.join(os.path.dirname(__file__), "files")

PAGE = """
<!doctype html><title>VulnApp</title>
<style>body{font-family:sans-serif;max-width:700px;margin:2em auto}nav a{margin-right:1em}</style>
<h1>VulnApp</h1>
<nav><a href="/">Home</a><a href="/login">Login</a><a href="/search">Search (SQLi)</a>
<a href="/hello">Hello (XSS)</a><a href="/guestbook">Guestbook (Stored XSS)</a>
<a href="/ping">Ping (Cmd Inj)</a><a href="/view?file=welcome.txt">File (Traversal)</a></nav><hr>
{{ body|safe }}
"""


def page(body):
    return render_template_string(PAGE, body=body)


def db():
    return sqlite3.connect(DB)


def init_db():
    c = db()
    c.executescript("""
        DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS products; DROP TABLE IF EXISTS comments;
        CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
        CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price REAL);
        CREATE TABLE comments(id INTEGER PRIMARY KEY, author TEXT, body TEXT);
        INSERT INTO users(username,password,role) VALUES('admin','admin123','admin'),('alice','password1','user');
        INSERT INTO products(name,price) VALUES('Widget',9.99),('Gadget',19.99),('Gizmo',4.50);
    """)
    c.commit()
    c.close()
    with open(os.path.join(FILES_DIR, "welcome.txt"), "w") as f:
        f.write("Welcome to VulnApp!\n")


@app.route("/")
def index():
    user = session.get("user")
    return page(f"<p>Intentionally vulnerable app for security practice.</p>"
                f"<p>Logged in as: {user or 'nobody'}</p>")


# VULN: SQL injection (auth bypass), e.g. username: admin' --
@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        u, p = request.form.get("username", ""), request.form.get("password", "")
        q = f"SELECT username FROM users WHERE username='{u}' AND password='{p}'"
        try:
            row = db().execute(q).fetchone()
        except Exception as e:
            return page(f"<pre>SQL error: {e}\nQuery: {q}</pre>")  # VULN: verbose errors
        if row:
            session["user"] = row[0]
            return redirect("/")
        msg = "<p style='color:red'>Invalid credentials</p>"
    return page(msg + """<form method=post>
        <input name=username placeholder=username> <input name=password type=password placeholder=password>
        <button>Login</button></form>""")


# VULN: SQL injection (UNION-based), e.g. ' UNION SELECT id,username||':'||password,0 FROM users --
@app.route("/search")
def search():
    term = request.args.get("q", "")
    q = f"SELECT id,name,price FROM products WHERE name LIKE '%{term}%'"
    try:
        rows = db().execute(q).fetchall()
    except Exception as e:
        return page(f"<pre>SQL error: {e}\nQuery: {q}</pre>")
    items = "".join(f"<li>{r[1]} - ${r[2]}</li>" for r in rows)
    return page(f"<form><input name=q value=''> <button>Search</button></form><ul>{items}</ul>")


# VULN: reflected XSS, e.g. /hello?name=<script>alert(1)</script>
@app.route("/hello")
def hello():
    return page(f"<h2>Hello, {request.args.get('name', 'stranger')}!</h2>")


# VULN: stored XSS, no escaping, no CSRF protection
@app.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    c = db()
    if request.method == "POST":
        c.execute("INSERT INTO comments(author,body) VALUES(?,?)",
                  (request.form.get("author", ""), request.form.get("body", "")))
        c.commit()
    rows = c.execute("SELECT author,body FROM comments").fetchall()
    posts = "".join(f"<p><b>{a}</b>: {b}</p>" for a, b in rows)
    return page("""<form method=post><input name=author placeholder=name>
        <input name=body placeholder=comment> <button>Post</button></form>""" + posts)


# VULN: OS command injection, e.g. host=127.0.0.1;id
@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    out = ""
    if host:
        out = subprocess.run(f"ping -c 1 -W 1 {host}", shell=True,
                             capture_output=True, text=True).stdout
    return page(f"<form><input name=host placeholder=127.0.0.1> <button>Ping</button></form><pre>{out}</pre>")


# VULN: path traversal, e.g. /view?file=../../../etc/passwd
@app.route("/view")
def view():
    name = request.args.get("file", "")
    try:
        with open(os.path.join(FILES_DIR, name)) as f:
            return page(f"<pre>{f.read()}</pre>")
    except Exception as e:
        return page(f"<pre>Error: {e}</pre>")


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
