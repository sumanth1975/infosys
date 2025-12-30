from flask import Flask, render_template, request, jsonify, session
import pytesseract
from PIL import Image
import os

from preprocess import load_and_preprocess
from train import trained_model
from clean import clean_text

# -------------------------------------------------
# APP CONFIG
# -------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates")
)

app.secret_key = "secret_key_123"

# -------------------------------------------------
# OCR CONFIG (Windows users)
# -------------------------------------------------
# Uncomment if Tesseract is not in PATH
# pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# -------------------------------------------------
# LOAD ML MODEL
# -------------------------------------------------
X, y, vectorizer = load_and_preprocess(
    os.path.join(BASE_DIR, "dataset", "fake_job_postings.csv")
)
model = trained_model(X, y)

# -------------------------------------------------
# TEMP USERS (replace with DB later)
# -------------------------------------------------
users = {
    "admin": {"password": "admin123", "role": "admin"},
    "user": {"password": "user123", "role": "user"}
}

# -------------------------------------------------
# ROUTES
# -------------------------------------------------
@app.route("/")
def home():
    # Single-page app → always load index.html
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = users.get(username)

    if user and user["password"] == password:
        session["role"] = user["role"]
        return jsonify({"role": user["role"]})

    return jsonify({"role": "invalid"})


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")

    if username in users:
        return jsonify({"success": False, "message": "User already exists"})

    users[username] = {
        "password": data.get("password"),
        "role": "user"
    }

    return jsonify({"success": True})


@app.route("/logout")
def logout():
    session.clear()
    return jsonify({"success": True})


@app.route("/predict", methods=["POST"])
def predict():
    text = request.form.get("text", "")

    # ---------------- OCR ----------------
    if "image" in request.files:
        img = request.files["image"]
        if img.filename:
            image = Image.open(img)
            ocr_text = pytesseract.image_to_string(image)
            text += " " + ocr_text

    if not text.strip():
        return jsonify({"error": "No text provided"})

    # ---------------- ML PREDICTION ----------------
    cleaned = clean_text(text)
    vector = vectorizer.transform([cleaned])
    prediction = int(model.predict(vector)[0])

    keywords = ["payment", "fee", "urgent", "whatsapp", "guaranteed"]
    flags = [k for k in keywords if k in cleaned]

    return jsonify({
        "result": "FAKE JOB " if prediction == 1 else "REAL JOB ",
        "prediction": prediction,
        "flags": flags,
        "length": len(text.split())
    })


# -------------------------------------------------
# RUN
# -------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
