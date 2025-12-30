from flask import Flask, render_template, request, redirect, session
import sqlite3, os
from src.predictor import predict_text, predict_image

app = Flask(__name__)
app.secret_key = "jobguard_secret"
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ---------- DATABASE ----------
def get_db():
    return sqlite3.connect("database.db")

def init_db():
    db = get_db()
    c = db.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS predictions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT,
        input_type TEXT,
        result TEXT
    )""")
    db.commit()
    db.close()

init_db()

# ---------- AUTH ----------
@app.route("/", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE email=? AND password=?",
            (email,password)
        ).fetchone()
        db.close()

        if user:
            session["user"] = email
            session["role"] = user[3]
            return redirect("/dashboard")
        return "Invalid credentials"
    return render_template("login.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        db = get_db()
        db.execute(
            "INSERT INTO users(email,password,role) VALUES(?,?,?)",
            (email,password,"user")
        )
        db.commit()
        db.close()
        return redirect("/")
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ---------- DASHBOARD ----------
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    if session["role"] == "admin":
        return redirect("/admin")
    return render_template("dashboard.html")

# ---------- DETECTION ----------
@app.route("/detect", methods=["GET","POST"])
def detect():
    result = None
    if request.method == "POST":
        if "jobtext" in request.form and request.form["jobtext"]:
            result = predict_text(request.form["jobtext"])
            db = get_db()
            db.execute(
                "INSERT INTO predictions(user,input_type,result) VALUES(?,?,?)",
                (session["user"],"Text",result)
            )
            db.commit()
            db.close()

        if "jobimage" in request.files:
            img = request.files["jobimage"]
            if img.filename:
                path = os.path.join(UPLOAD_FOLDER, img.filename)
                img.save(path)
                result = predict_image(path)
                db = get_db()
                db.execute(
                    "INSERT INTO predictions(user,input_type,result) VALUES(?,?,?)",
                    (session["user"],"Image",result)
                )
                db.commit()
                db.close()

    return render_template("detect.html", result=result)

# ---------- ADMIN ----------
@app.route("/admin")
def admin():
    db = get_db()
    users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    scans = db.execute("SELECT COUNT(*) FROM predictions").fetchone()[0]
    fake = db.execute(
        "SELECT COUNT(*) FROM predictions WHERE result LIKE '%FAKE%'"
    ).fetchone()[0]
    db.close()
    return render_template(
        "admin.html",
        users=users,
        scans=scans,
        fake=fake
    )

if __name__ == "__main__":
    app.run(debug=True)
