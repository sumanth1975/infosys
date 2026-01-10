from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
import mysql.connector
from mysql.connector import Error
import bcrypt
from datetime import datetime
import joblib
from functools import wraps
import os
from flask import request
from PIL import Image
import pytesseract
from clean import clean_text
import jwt
from datetime import datetime, timedelta
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"



app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = 'your-secret-key-here'
JWT_SECRET = "jwt-secret-key-123"
JWT_ALGO = "HS256"
JWT_EXP_MINUTES = 60

CORS(app)

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',  # Your MySQL username
    'password': '1975',  # Your MySQL password
    'database': 'job_fraud_db'
}
def create_jwt(user):
    payload = {
        "user_id": user["id"],
        "role": user["role"],
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXP_MINUTES)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

# Load ML model and preprocessing objects

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(BASE_DIR, "model", "job_model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "model", "tfidf_vectorizer.pkl")

try:
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    MODEL_LOADED = True
    print(" Trained model + vectorizer loaded")
except Exception as e:
    MODEL_LOADED = False
    model = None
    vectorizer = None
    print("❌ Model load failed:", e)
def predict_from_text(text):
    if not MODEL_LOADED:
        return "Uncertain", 50

    cleaned = clean_text(text)
    vector = vectorizer.transform([cleaned])
    pred = model.predict(vector)[0]

    label = "Fake" if pred == 1 else "Real"
    confidence = 80 if label == "Real" else 75

    return label, confidence



def get_db_connection():
    try:
        return mysql.connector.connect(
            host="localhost",
            user="root",
            password="1975",
            database="job_fraud_db",
            auth_plugin="mysql_native_password"
        )
    except Exception as e:
        print("❌ DB CONNECTION ERROR:", e)
        return None


# Authentication decorator
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization")

        if not auth:
            return jsonify({"success": False, "message": "Token missing"}), 401

        try:
            token = auth.replace("Bearer ", "")
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])

            request.user_id = payload["user_id"]
            request.role = payload["role"]

        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "message": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "message": "Invalid token"}), 401

        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.role != "admin":
            return jsonify({"success": False, "message": "Admin access only"}), 403
        return f(*args, **kwargs)
    return wrapper




# Routes
@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/dashboard')
def dashboard():
    return app.send_static_file('dashboard.html')

@app.route('/checkjob')
def check_job():
    return app.send_static_file('checkjob.html')

@app.route('/admin')
def admin_page():
    return app.send_static_file('admin.html')


# Authentication routes
@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.json
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        
        if not all([name, email, password]):
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        connection = get_db_connection()
        if not connection:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        
        cursor = connection.cursor()
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            cursor.close()
            connection.close()
            return jsonify({'success': False, 'message': 'Email already registered'}), 400
        
        # Insert new user
        cursor.execute(
            "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
            (name, email, hashed_password.decode('utf-8'))
        )
        connection.commit()
        
        user_id = cursor.lastrowid
        
        cursor.close()
        connection.close()
        
        return jsonify({
            'success': True,
            'message': 'Account created successfully! Please sign in.',
            'user_id': user_id
        })
        
    except Exception as e:
        print(f"Signup error: {e}")
        return jsonify({'success': False, 'message': 'An error occurred during signup'}), 500

@app.route('/signin', methods=['POST'])
def signin():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        
        if not all([email, password]):
            return jsonify({'success': False, 'message': 'Email and password are required'}), 400
        
        connection = get_db_connection()
        if not connection:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        
        cursor = connection.cursor(dictionary=True)
        
        # Get user by email
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        cursor.close()
        connection.close()
        
        if not user:
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
        
        # Verify password
        if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            # Remove password from response
            user.pop('password')
            token = create_jwt(user)

            return jsonify({
            "success": True,
            "token": token,
            "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"]
        }
        })

        else:
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
            
    except Exception as e:
        print(f"Signin error: {e}")
        return jsonify({'success': False, 'message': 'An error occurred during signin'}), 500

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()

    email = data.get("email")
    password = data.get("password")
    confirm_password = data.get("confirm_password")

    if not email or not password or not confirm_password:
        return jsonify({
            "success": False,
            "message": "All fields are required"
        }), 400

    if password != confirm_password:
        return jsonify({
            "success": False,
            "message": "Passwords do not match"
        }), 400

    if len(password) < 6:
        return jsonify({
            "success": False,
            "message": "Password must be at least 6 characters"
        }), 400

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT id FROM users WHERE email=%s", (email,))
    user = cur.fetchone()

    if not user:
        cur.close()
        conn.close()
        return jsonify({
            "success": False,
            "message": "Email not registered"
        }), 404

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    cur.execute(
        "UPDATE users SET password=%s WHERE email=%s",
        (hashed_password.decode('utf-8'), email)
    )

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Password reset successful. Please login."
    })


# History route
@app.route('/get-history', methods=['GET'])
@login_required
def get_history():
    try:
        user_id = request.user_id

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Text predictions
        cursor.execute("""
            SELECT id, job_title AS title, prediction, confidence, created_at,
                   'text' AS source
            FROM job_checks
            WHERE user_id = %s
        """, (user_id,))
        job_history = cursor.fetchall()

        # Image predictions
        cursor.execute("""
            SELECT id, image_name AS title, prediction, confidence, created_at,
                   'image' AS source
            FROM image_checks
            WHERE user_id = %s
        """, (user_id,))
        image_history = cursor.fetchall()

        cursor.close()
        connection.close()

        full_history = job_history + image_history
        full_history.sort(key=lambda x: x['created_at'], reverse=True)

        return jsonify({
            'success': True,
            'count': len(full_history),
            'history': full_history[:50]
        })

    except Exception as e:
        print(" History Error:", e)
        return jsonify({
            'success': False,
            'message': 'Failed to fetch history'
        }), 500


# Prediction route
@app.route('/predict-job', methods=['POST'])
@login_required
def predict_job():
    try:
        data = request.json
        user_id = request.user_id

        text = (
            str(data.get("title", "")) + " " +
            str(data.get("company_profile", "")) + " " +
            str(data.get("description", "")) + " " +
            str(data.get("requirements", "")) + " " +
            str(data.get("benefits", ""))
        )

        prediction, confidence = predict_from_text(text)

        # Save to DB
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor()

            cursor.execute(
                """
                INSERT INTO job_checks (user_id, job_title, prediction, confidence)
                VALUES (%s, %s, %s, %s)
                """,
                (user_id, data.get('title', 'Untitled Job'), prediction, confidence)
            )

            record_id = cursor.lastrowid  

            connection.commit()
            cursor.close()
            connection.close()

            return jsonify({
                "success": True,
                "prediction": prediction,
                "confidence": confidence,
                "record_id": record_id
            })

        return jsonify({
            "success": False,
            "message": "Database connection failed"
        }), 500

    except Exception as e:
        print("Prediction error:", e)
        return jsonify({
            "success": False,
            "message": "Prediction failed"
        }), 500

@app.route("/predict-image", methods=["POST"])
@login_required
def predict_image():
    try:
        user_id = request.user_id


        if "image" not in request.files:
            return jsonify({"success": False, "message": "No image uploaded"}), 400

        image_file = request.files["image"]
        image_name = image_file.filename
        image = Image.open(image_file)

        extracted_text = pytesseract.image_to_string(image)

        if not extracted_text or len(extracted_text.strip()) < 20:
            prediction, confidence = "Uncertain", 50
        else:
            prediction, confidence = predict_from_text(extracted_text)

        #  SAVE IMAGE PREDICTION
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO image_checks (user_id, image_name, prediction, confidence)
            VALUES (%s, %s, %s, %s)
        """, (user_id, image_name, prediction, confidence))
        record_id = cursor.lastrowid

        connection.commit()
        cursor.close()
        connection.close()

        return jsonify({
            "success": True,
            "prediction": prediction,
            "confidence": confidence,
            "record_id": record_id 
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "message": "Image prediction failed"
        }), 500

# ================= ADMIN ROUTES =================

@app.route('/admin/predictions', methods=['GET'])
@login_required
@admin_required
def admin_predictions():
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        cur.execute("""
            SELECT 
                u.id AS user_id,
                u.name,
                u.email,
                u.role,
                jc.job_title,
                jc.prediction,
                jc.confidence,
                jc.created_at
            FROM job_checks jc
            JOIN users u ON u.id = jc.user_id
            ORDER BY jc.created_at DESC
        """)

        data = cur.fetchall()

        # MANUAL SERIALIZATION (IMPORTANT)
        for row in data:
            row["date"] = row["created_at"].strftime("%Y-%m-%d")
            row["time"] = row["created_at"].strftime("%H:%M:%S")
            del row["created_at"]

        cur.close()
        conn.close()

        return jsonify({
            "success": True,
            "data": data
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500


@app.route('/admin/promote/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def promote_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        "UPDATE users SET role='admin' WHERE id=%s",
        (user_id,)
    )

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({'success': True})


@app.route('/admin/demote/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def demote_user(user_id):
    admin_id = request.user_id

    if user_id == admin_id:
        return jsonify({
            'success': False,
            'message': 'Cannot demote yourself'
        }), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET role='user' WHERE id=%s", (user_id,))
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({'success': True})


@app.route('/admin/download-history', methods=['GET'])
@login_required
@admin_required
def download_history():
    conn = get_db_connection()
    cur = conn.cursor()

    # 🔹 JOB PREDICTIONS
    cur.execute("""
        SELECT 
            u.name,
            'JOB' AS type,
            jc.job_title AS title,
            jc.prediction,
            jc.confidence,
            jc.created_at
        FROM job_checks jc
        JOIN users u ON u.id = jc.user_id
    """)
    jobs = cur.fetchall()

    # 🔹 IMAGE PREDICTIONS
    cur.execute("""
        SELECT 
            u.name,
            'IMAGE' AS type,
            ic.image_name AS title,
            ic.prediction,
            ic.confidence,
            ic.created_at
        FROM image_checks ic
        JOIN users u ON u.id = ic.user_id
    """)
    images = cur.fetchall()

    cur.close()
    conn.close()

    # 🔹 MERGE BOTH
    data = jobs + images

    # 🔹 SORT BY DATE (LATEST FIRST)
    data.sort(key=lambda x: x[5], reverse=True)

    # 🔹 CREATE CSV
    import csv
    from io import StringIO
    from flask import Response

    si = StringIO()
    writer = csv.writer(si)

    writer.writerow(["User", "Type", "Title", "Prediction", "Confidence", "Date"])

    for row in data:
        writer.writerow([
            row[0],                      # user
            row[1],                      # type (JOB / IMAGE)
            row[2],                      # title
            row[3],                      # prediction
            row[4],                      # confidence
            row[5].strftime("%Y-%m-%d %H:%M:%S")
        ])

    return Response(
        si.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment;filename=all_predictions.csv"
        }
    )

@app.route('/admin/history', methods=['GET'])
@login_required
@admin_required
def admin_history():
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        # 🔹 JOB HISTORY
        cur.execute("""
            SELECT 
    u.id AS user_id,
    u.name,
    u.email,
    u.role,
    jc.job_title AS title,
    jc.prediction,
    jc.confidence,
    jc.feedback_status,   -- ⭐ ADD
    jc.created_at,
    'job' AS source
FROM job_checks jc
JOIN users u ON u.id = jc.user_id

        """)
        jobs = cur.fetchall()

        # 🔹 IMAGE HISTORY
        cur.execute("""
           SELECT 
    u.id AS user_id,
    u.name,
    u.email,
    u.role,
    ic.image_name AS title,
    ic.prediction,
    ic.confidence,
    ic.feedback_status,   
    ic.created_at,
    'image' AS source
FROM image_checks ic
JOIN users u ON u.id = ic.user_id

        """)
        images = cur.fetchall()

        cur.close()
        conn.close()

        data = jobs + images

        # FIX: datetime → string (MANDATORY)
        for row in data:
            row["date"] = row["created_at"].strftime("%Y-%m-%d")
            row["time"] = row["created_at"].strftime("%H:%M:%S")
            del row["created_at"]

        # Latest first
        data.sort(key=lambda x: (x["date"], x["time"]), reverse=True)

        return jsonify({
            "success": True,
            "data": data
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500
    
@app.route('/admin/statistics', methods=['GET'])
@login_required
@admin_required
def admin_statistics():
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # ---------- TOTAL REAL / FAKE ----------
        cur.execute("""
            SELECT 
                SUM(LOWER(prediction)='fake'),
                SUM(LOWER(prediction)='real')
            FROM job_checks
        """)
        job_fake, job_real = cur.fetchone()

        cur.execute("""
            SELECT 
                SUM(LOWER(prediction)='fake'),
                SUM(LOWER(prediction)='real')
            FROM image_checks
        """)
        img_fake, img_real = cur.fetchone()

        fake = (job_fake or 0) + (img_fake or 0)
        real = (job_real or 0) + (img_real or 0)

        # ---------- FLAGGED COUNT ----------
        cur.execute("""
            SELECT COUNT(*) FROM job_checks WHERE feedback_status='flagged'
        """)
        job_flagged = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM image_checks WHERE feedback_status='flagged'
        """)
        image_flagged = cur.fetchone()[0]

        flagged_count = (job_flagged or 0) + (image_flagged or 0)

        # ---------- DAILY COUNTS ----------
        cur.execute("""
            SELECT DATE(created_at), COUNT(*)
            FROM job_checks
            GROUP BY DATE(created_at)
            ORDER BY DATE(created_at)
        """)
        rows = cur.fetchall()

        labels = [str(r[0]) for r in rows]
        counts = [r[1] for r in rows]

        cur.close()
        conn.close()

        return jsonify({
            "success": True,
            "stats": {
                "fake": fake,
                "real": real,
                "flagged": flagged_count
            },
            "daily": {
                "labels": labels,
                "counts": counts
            }
        })

    except Exception as e:
        print("ADMIN STAT ERROR:", e)
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500



@app.route('/user/download-history', methods=['GET'])
@login_required
def download_user_history():
    try:
        user_id = request.user_id


        conn = get_db_connection()
        cur = conn.cursor()

        # 🔹 Job history
        cur.execute("""
            SELECT 
                jc.job_title,
                jc.prediction,
                jc.confidence,
                jc.created_at,
                'job' AS source
            FROM job_checks jc
            WHERE jc.user_id = %s
        """, (user_id,))
        jobs = cur.fetchall()

        # 🔹 Image history
        cur.execute("""
            SELECT 
                ic.image_name,
                ic.prediction,
                ic.confidence,
                ic.created_at,
                'image' AS source
            FROM image_checks ic
            WHERE ic.user_id = %s
        """, (user_id,))
        images = cur.fetchall()

        cur.close()
        conn.close()

        import csv
        from io import StringIO
        from flask import Response

        si = StringIO()
        writer = csv.writer(si)
        writer.writerow(["Type", "Title", "Prediction", "Confidence", "Date"])

        for row in jobs:
            writer.writerow([
                row[4].upper(),
                row[0],
                row[1],
                row[2],
                row[3]
            ])

        for row in images:
            writer.writerow([
                row[4].upper(),
                row[0],
                row[1],
                row[2],
                row[3]
            ])

        return Response(
            si.getvalue(),
            mimetype="text/csv",
            headers={
                "Content-Disposition": "attachment;filename=my_prediction_history.csv"
            }
        )

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500

@app.route('/user/statistics', methods=['GET'])
@login_required
def user_statistics():
    try:
        user_id = request.user_id

        conn = get_db_connection()
        cur = conn.cursor()

        # ---------- TEXT JOB CHECKS ----------
        cur.execute("""
            SELECT 
                COUNT(*) AS total,
                SUM(LOWER(prediction)='fake'),
                SUM(LOWER(prediction)='real')
            FROM job_checks
            WHERE user_id=%s
        """, (user_id,))
        text_total, text_fake, text_real = cur.fetchone()

        # ---------- IMAGE JOB CHECKS ----------
        cur.execute("""
            SELECT 
                COUNT(*) AS total,
                SUM(LOWER(prediction)='fake'),
                SUM(LOWER(prediction)='real')
            FROM image_checks
            WHERE user_id=%s
        """, (user_id,))
        img_total, img_fake, img_real = cur.fetchone()

        cur.close()
        conn.close()

        fake_jobs = (text_fake or 0) + (img_fake or 0)
        real_jobs = (text_real or 0) + (img_real or 0)

        return jsonify({
            "success": True,
            "stats": {
                "total_checks": text_total + img_total,
                "text_checks": text_total,
                "image_checks": img_total,
                "fake_jobs": fake_jobs,
                "real_jobs": real_jobs
            }
        })

    except Exception as e:
        print("STATISTICS ERROR:", e)
        return jsonify({
            "success": False,
            "message": "Statistics fetch failed"
        }), 500

@app.route("/user/feedback", methods=["POST"])
@login_required
def user_feedback():
    try:
        data = request.json
        user_id = request.user_id

        record_id = data["record_id"]
        feedback = data["feedback"]
        check_type = data["check_type"]

        status = "flagged" if feedback == "wrong" else None

        conn = get_db_connection()
        cur = conn.cursor()

        if check_type == "job":
            cur.execute("""
                UPDATE job_checks
                SET feedback_status=%s
                WHERE id=%s AND user_id=%s
            """, (status, record_id, user_id))

        elif check_type == "image":
            cur.execute("""
                UPDATE image_checks
                SET feedback_status=%s
                WHERE id=%s AND user_id=%s
            """, (status, record_id, user_id))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"success": True})

    except Exception as e:
        print("FEEDBACK ERROR:", e)
        return jsonify({"success": False}), 500

@app.route("/admin/retrain-model", methods=["POST"])
@login_required
@admin_required
def retrain_model():
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 🔐 BACKEND SAFETY CHECK
        cur.execute("""
            SELECT COUNT(*) FROM job_checks WHERE feedback_status='flagged'
        """)
        job_flagged = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM image_checks WHERE feedback_status='flagged'
        """)
        image_flagged = cur.fetchone()[0]

        flagged_count = (job_flagged or 0) + (image_flagged or 0)

        cur.close()
        conn.close()

        if flagged_count <= 20:
            return jsonify({
                "success": False,
                "message": "Retrain allowed only when flagged count > 20"
            }), 400

        # 🔁 RETRAIN MODEL (uses your existing main.py)
        os.system("python main.py")

        return jsonify({
            "success": True,
            "message": "Model retrained successfully"
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500



if __name__ == '__main__':
    # Create model directory if it doesn't exist
    os.makedirs('model', exist_ok=True)
    
    # Create tables if they don't exist
    try:
        connection = get_db_connection()
        if connection:
            cursor = connection.cursor()
            
            # Check if users table exists
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(100),
                    email VARCHAR(100),
                    password VARCHAR(255),
                    role VARCHAR(20) DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("""
    CREATE TABLE IF NOT EXISTS job_checks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        job_title VARCHAR(255),
        prediction VARCHAR(20),
        confidence DECIMAL(5,2),
        feedback_status VARCHAR(20) DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
""")

            cursor.execute("""
    CREATE TABLE IF NOT EXISTS image_checks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        image_name VARCHAR(255),
        prediction VARCHAR(20),
        confidence DECIMAL(5,2),
        feedback_status VARCHAR(20) DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
""")

            
            connection.commit()
            cursor.close()
            connection.close()
            print("Database tables created/verified successfully")
    except Exception as e:
        print(f"Database setup error: {e}")
    
    # Run the app
    print("\n" + "="*50)
    print("Fake Job Prediction System")
    print("="*50)
    print("App running on: http://localhost:5000")
    print("ML Model Loaded:", MODEL_LOADED)
    print("\nEndpoints:")
    print("- http://localhost:5000/ (Sign In/Up)")
    print("- http://localhost:5000/dashboard")
    print("- http://localhost:5000/checkjob")
    print("- POST http://localhost:5000/signup")
    print("- POST http://localhost:5000/signin")
    print("="*50 + "\n")
    @app.route('/test', methods=['GET'])
    def test():
        return jsonify({
            'success': True,
            'message': 'Backend is running',
            'timestamp': datetime.now().isoformat()
        })
    app.run(debug=True, port=5000)