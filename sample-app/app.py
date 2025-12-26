#!/usr/bin/env python3
"""
Vulnerable Flask Application for Security Testing
⚠️ WARNING: DO NOT USE IN PRODUCTION ⚠️

This application contains intentional security vulnerabilities for testing purposes.
"""

from flask import Flask, request, jsonify, render_template_string
import sqlite3
import hashlib
import os

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded secrets
API_KEY = "sk-1234567890abcdef"  # pragma: allowlist secret
DATABASE_PASSWORD = "super_secret_password_123"  # pragma: allowlist secret
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret

# VULNERABILITY 2: Debug mode enabled in production
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'insecure-secret-key-12345'

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database with sample data"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    # Insert admin user with weak password
    cursor.execute('''
        INSERT INTO users (username, password, email, role) 
        VALUES (?, ?, ?, ?)
    ''', ('admin', hashlib.md5(b'admin123').hexdigest(), 'admin@example.com', 'admin'))
    
    conn.commit()
    conn.close()

@app.route('/')
def home():
    """Home page"""
    return jsonify({
        "message": "Vulnerable Flask Application",
        "version": "1.0",
        "endpoints": [
            "/health",
            "/login",
            "/register",
            "/user/<id>",
            "/search",
            "/api/data"
        ]
    })

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy"}), 200

@app.route('/login', methods=['POST'])
def login():
    """
    VULNERABILITY 3: SQL Injection
    User can inject SQL: ' OR '1'='1' --
    """
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # Vulnerable SQL query - concatenation without parameterization
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(query)  # SQL Injection vulnerability
        user = cursor.fetchone()
        
        if user:
            return jsonify({
                "success": True,
                "message": "Login successful",
                "user": dict(user)
            })
        else:
            return jsonify({"success": False, "message": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/register', methods=['POST'])
def register():
    """
    VULNERABILITY 4: Weak password hashing (MD5)
    MD5 is cryptographically broken and should not be used
    """
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')
    
    if not all([username, password, email]):
        return jsonify({"error": "Missing required fields"}), 400
    
    # VULNERABILITY: Using MD5 for password hashing
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            (username, password_hash, email)
        )
        conn.commit()
        return jsonify({"success": True, "message": "User registered"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409
    finally:
        conn.close()

@app.route('/user/<user_id>')
def get_user(user_id):
    """
    VULNERABILITY 5: SQL Injection via path parameter
    No input validation on user_id
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Vulnerable - direct string interpolation
    query = f"SELECT * FROM users WHERE id={user_id}"
    
    try:
        cursor.execute(query)  # SQL Injection
        user = cursor.fetchone()
        
        if user:
            return jsonify(dict(user))
        else:
            return jsonify({"error": "User not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/search')
def search():
    """
    VULNERABILITY 6: Cross-Site Scripting (XSS)
    Reflects user input without sanitization
    """
    query = request.args.get('q', '')
    
    # VULNERABILITY: Rendering user input without escaping
    html = f"""
    <html>
        <head><title>Search Results</title></head>
        <body>
            <h1>Search Results for: {query}</h1>
            <p>You searched for: {query}</p>
        </body>
    </html>
    """
    
    return render_template_string(html)  # XSS vulnerability

@app.route('/api/data')
def api_data():
    """
    VULNERABILITY 7: Missing authentication
    Sensitive data exposed without authentication
    """
    # Exposing sensitive information
    sensitive_data = {
        "api_key": API_KEY,
        "database_password": DATABASE_PASSWORD,
        "aws_access_key": AWS_ACCESS_KEY,
        "credit_cards": [
            "4532-1234-5678-9010",
            "5425-2334-3010-9903"
        ],
        "ssn": ["123-45-6789", "987-65-4321"],
        "internal_ips": ["192.168.1.100", "10.0.0.50"]
    }
    
    return jsonify(sensitive_data)

@app.route('/file')
def read_file():
    """
    VULNERABILITY 8: Path Traversal
    Allows reading arbitrary files
    """
    filename = request.args.get('name', 'default.txt')
    
    try:
        # VULNERABILITY: No path validation
        with open(filename, 'r') as f:
            content = f.read()
        return jsonify({"filename": filename, "content": content})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/eval', methods=['POST'])
def evaluate():
    """
    VULNERABILITY 9: Code Injection
    Eval on user input
    """
    code = request.form.get('code', '')
    
    try:
        # CRITICAL VULNERABILITY: eval() on user input
        result = eval(code)
        return jsonify({"result": str(result)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/admin')
def admin_panel():
    """
    VULNERABILITY 10: Broken Access Control
    No authorization check
    """
    return jsonify({
        "message": "Admin Panel",
        "actions": ["delete_users", "view_logs", "change_settings"],
        "warning": "This should be protected but it's not!"
    })

@app.errorhandler(404)
def not_found(error):
    """
    VULNERABILITY 11: Information disclosure in error messages
    """
    return jsonify({
        "error": "Not found",
        "path": request.path,
        "method": request.method,
        "headers": dict(request.headers),
        "ip": request.remote_addr
    }), 404

@app.errorhandler(500)
def internal_error(error):
    """Detailed error messages (information disclosure)"""
    return jsonify({
        "error": "Internal server error",
        "details": str(error),
        "type": type(error).__name__
    }), 500

if __name__ == '__main__':
    print("=" * 60)
    print("⚠️  WARNING: VULNERABLE APPLICATION")
    print("=" * 60)
    print("This application contains intentional security flaws.")
    print("DO NOT deploy this in production!")
    print("=" * 60)
    
    init_db()
    
    # VULNERABILITY 12: Running on all interfaces (0.0.0.0)
    # VULNERABILITY 13: Running as root user (in Docker)
    app.run(host='0.0.0.0', port=8080, debug=True)
