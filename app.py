from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash

import requests
import os
import json
import re
import hashlib
import secrets
import time
from functools import wraps

app = Flask(__name__)

app.secret_key = "ShinchanYo"
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

GOOGLE_MAPS_API_KEY = "AIzaSyCaEMcqU_EpGBw71sLTBSq_sywfPPAKJyc"
AIR_QUALITY_API_KEY = "AIzaSyC3GAspOWXx5A703i4KwHqmPJWoql20hc0"

BASE_DIR = r"C:\\Users\\tejas\\Python Projects\\Google Maps Projects\\Air Quality Google maps Webapp\\Air_Quality 3"
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

LOC_DB = os.path.join(DATA_DIR, "air_quality.db")
USER_DB=os.path.join(DATA_DIR, "user.db")

# Initialize the database
def init_db():
    conn = sqlite3.connect(LOC_DB)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS air_quality_index (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            latitude REAL,
            longitude REAL,
            response TEXT
        )
    ''')
    conn.commit()
    conn.close()


    conn = sqlite3.connect(USER_DB)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# User registration and authentication
def hash_password(password):
    return generate_password_hash(password)


def verify_password(stored_password_hash, password):
    return check_password_hash(stored_password_hash, password)

def is_valid_password(password):
    """Check if password meets complexity requirements"""
    # At least 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special character
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

def is_valid_email(email):
    """Check if email has valid format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Store location in the database
def store_location(name, latitude, longitude):
    conn = sqlite3.connect(LOC_DB)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO air_quality_index (name, latitude, longitude, response) VALUES (?, ?, ?, NULL)',
                   (name, latitude, longitude))
    conn.commit()
    conn.close()

@app.route('/')
def home():
    if "user_id" in session:  
        return redirect(url_for('dashboard'))  # User is logged in, go to dashboard
    return redirect(url_for('login'))  # User is NOT logged in, go to login page

@app.route('/index')
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        
        conn = sqlite3.connect(USER_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT id, password_hash, name FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()
        
        if user and verify_password(user[1], password):
            session["user_id"] = user[0]
            session["user_name"] = user[2]
            session["user_email"] = email
            
            # Update last login time
            conn = sqlite3.connect(USER_DB)
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user[0],))
            conn.commit()
            conn.close()
            
            # Redirect to dashboard
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password", "error")
    
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        username = request.form.get("username")

        
        # Validate input
        if not all([email, password, confirm_password, username]):
            flash("All fields are required", "error")
            return render_template("register.html")
        
        if not is_valid_email(email):
            flash("Invalid email format", "error")
            return render_template("register.html")
        
        if password != confirm_password:
            flash("Passwords do not match", "error")
            return render_template("register.html")
        
        if not is_valid_password(password):
            flash("Password should be at least 8 characters with at least 1 uppercase letter, 1 lowercase letter, 1 digit, and 1 special character", "error")
            return render_template("register.html")
        
        # Check if email already exists
        conn = sqlite3.connect(USER_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            conn.close()
            flash("Email already registered", "error")
            return render_template("register.html")
        
        # Create new user
        password_hash = hash_password(password)
        cursor.execute("INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)", 
                      (email, password_hash, username))
        conn.commit()
        conn.close()
        
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))
    
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("user_name", None)
    session.pop("user_email", None)
    flash("You have been logged out", "info")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user_name=session.get("user_name"), current_user=session)


@app.route("/profile")
@login_required
def profile():
    conn = sqlite3.connect(USER_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT email, name, created_at, last_login FROM users WHERE id = ?", (session["user_id"],))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        flash("User not found", "error")
        return redirect(url_for("dashboard"))
    
    user_data = {
        "email": user[0],
        "name": user[1],
        "created_at": user[2],
        "last_login": user[3]
    }
    
    return render_template("profile.html")

@app.route("/reset_password", methods=["GET", "POST"])
@login_required
def reset_password():
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")
        
        # Validate input
        if not all([current_password, new_password, confirm_password]):
            flash("All fields are required", "error")
            return render_template("reset_password.html")
        
        if new_password != confirm_password:
            flash("New passwords do not match", "error")
            return render_template("reset_password.html")
        
        if not is_valid_password(new_password):
            flash("Password should be at least 8 characters with at least 1 uppercase letter, 1 lowercase letter, 1 digit, and 1 special character", "error")
            return render_template("reset_password.html")
        
        # Verify current password
        conn = sqlite3.connect(USER_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE id = ?", (session["user_id"],))
        stored_password_hash = cursor.fetchone()[0]
        
        if not verify_password(stored_password_hash, current_password):
            conn.close()
            flash("Current password is incorrect", "error")
            return render_template("reset_password.html")
        
        # Update password
        new_password_hash = hash_password(new_password)
        cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", 
                      (new_password_hash, session["user_id"]))
        conn.commit()
        conn.close()
        
        flash("Password updated successfully", "success")
        return redirect(url_for("profile"))
    
    return render_template("reset_password.html")

# AQI Web Application
# Fetch latitude & longitude from Google Maps API
def get_lat_long(location_name):
    url = f"https://maps.googleapis.com/maps/api/geocode/json?address={location_name}&key={GOOGLE_MAPS_API_KEY}"
    response = requests.get(url).json()
    if response["status"] == "OK":
        lat = response["results"][0]["geometry"]["location"]["lat"]
        lng = response["results"][0]["geometry"]["location"]["lng"]
        return lat, lng
    return None, None

@app.route("/process_locations", methods=["POST"])
def process_locations():
    try:
        file = request.files["file"]
        file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(file_path)

        with open(file_path, "r", encoding="utf-8") as f:
            locations = [line.strip() for line in f.readlines()]

        extracted_data = []

        for location in locations:
            latitude, longitude = get_lat_long(location)
            if latitude and longitude:
                store_location(location, latitude, longitude)
                extracted_data.append({"name": location, "latitude": latitude, "longitude": longitude})

        return jsonify({"message": "Locations extracted successfully!", "data": extracted_data})

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    



# Fetch all stored locations from the database
def get_stored_locations():
    conn = sqlite3.connect(LOC_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT name, latitude, longitude FROM air_quality_index")
    locations = [{"name": row[0], "latitude": row[1], "longitude": row[2]} for row in cursor.fetchall()]
    conn.close()
    return locations


# Fetch air quality for a given latitude and longitude
def get_air_quality(lat, lng):
    """Fetch AQI data from Google API for given coordinates."""
    url = f"https://airquality.googleapis.com/v1/currentConditions:lookup?key={AIR_QUALITY_API_KEY}"
    headers = {"Content-Type": "application/json"}
    payload = {"location": {"latitude": lat, "longitude": lng}}

    response = requests.post(url, json=payload, headers=headers)
    print(response)
    if response.status_code == 200:
        return response.text  # Store raw JSON response as a string
    else:
        return json.dumps({"error": f"Request failed with status code {response.status_code}", "details": response.text})

# Store air quality data in the database
def store_air_quality(latitude, longitude, response):
    """Store AQI response in the database."""
    conn = sqlite3.connect(LOC_DB)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO air_quality (response)
        VALUES (?)
    ''', ( json.dumps(response)))
    
    conn.commit()
    conn.close()

# Fetch stored locations from the database and update AQI
@app.route("/fetch_and_store_aqi", methods=["GET"])
def fetch_and_store_aqi():
    """Fetch AQI data for all stored locations and save it to the database."""
    conn = sqlite3.connect(LOC_DB)
    cursor = conn.cursor()
    
    # Fetch all locations
    cursor.execute("SELECT name, latitude, longitude FROM air_quality_index")
    locations = cursor.fetchall()
    
    for name, lat, lng in locations:
        aqi_response = get_air_quality(lat, lng)  # Fetch AQI using Google API
        print(aqi_response)  # Debugging
        
        # Convert AQI response to JSON string
        #aqi_json = json.dumps(aqi_response)  
        
        # Store AQI response in the database
        cursor.execute('''
            UPDATE air_quality_index
            SET response = ?
            WHERE name = ? AND latitude = ? AND longitude = ?;
        ''', (aqi_response, name, lat, lng))
        
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "AQI data stored successfully!"})




@app.route("/get_stored_locations", methods=["GET"])
def fetch_stored_locations():
    conn = sqlite3.connect(LOC_DB)
    cursor = conn.cursor()
    
    cursor.execute("SELECT name, latitude, longitude FROM air_quality_index")
    locations = [{"name": row[0], "latitude": row[1], "longitude": row[2]} for row in cursor.fetchall()]
    
    conn.close()
    return jsonify(locations)

@app.route("/fetch_aqi_data", methods=["POST"])
def fetch_aqi_data():
    """Trigger AQI fetching for all stored locations."""
    fetch_and_store_aqi()
    return jsonify({"message": "AQI data updated successfully!"})

'''@app.route("/fetch_aqi", methods=["POST"])
def fetch_aqi():
    """API endpoint to fetch and store AQI for all stored locations."""
    try:
        fetch_and_store_aqi()
        return jsonify({"message": "AQI data fetched and stored successfully!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500'''


@app.route("/get_stored_aqi", methods=["GET"])
def fetch_stored_aqi():
    """Fetch stored AQI data from the database."""
    conn = sqlite3.connect(LOC_DB)
    cursor = conn.cursor()
    
    cursor.execute("SELECT name, latitude, longitude, response FROM air_quality_index")
    data = cursor.fetchall()
    conn.close()

    results = []
    for location_name, lat, lng, raw_response in data:
        try:
            # The response might be double-encoded JSON
            try:
                response_json = json.loads(raw_response)
                if isinstance(response_json, str):
                    response_json = json.loads(response_json)
            except:
                response_json = json.loads(raw_response)
            
            # Extract the data from the correct structure
            indexes = response_json.get("indexes", [])
            if indexes and len(indexes) > 0:
                aqi_value = indexes[0].get("aqi")
                category = indexes[0].get("category", "Unknown")
                color_data = indexes[0].get("color", {})
                dominant_pollutant = indexes[0].get("dominantPollutant", "Unknown")
                
                # Convert RGB to hex color for the map
                r = int(color_data.get("red", 0.5) * 255)
                g = int(color_data.get("green", 0.5) * 255) 
                b = int(color_data.get("blue", 0.5) * 255) if "blue" in color_data else 0
                color_hex = f"#{r:02x}{g:02x}{b:02x}"
            else:
                aqi_value = None
                category = "Unknown"
                color_hex = "#808080"  # Default gray
                dominant_pollutant = "Unknown"
                
        except (json.JSONDecodeError, TypeError) as e:
            print(f"Error parsing response for {location_name}: {e}")
            aqi_value = None
            category = "Unknown"
            color_hex = "#808080"  # Default gray
            dominant_pollutant = "Unknown"

        results.append({
            "location_name": location_name,
            "latitude": lat,
            "longitude": lng,
            "aqi": aqi_value,
            "category": category,
            "color": color_hex,
            "dominant_pollutant": dominant_pollutant
        })

    return jsonify(results)

#for extrawebpages

@app.route("/analytics")
@login_required
def analytics():
    # Get air quality data for analytics
    conn = sqlite3.connect(LOC_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT name, latitude, longitude, response FROM air_quality_index")
    data = cursor.fetchall()
    conn.close()
    
    analytics_data = []
    for location_name, lat, lng, raw_response in data:
        try:
            response_json = json.loads(raw_response)
            # Extract relevant analytics data
            if "indexes" in response_json and len(response_json["indexes"]) > 0:
                aqi_value = response_json["indexes"][0].get("aqi")
                category = response_json["indexes"][0].get("category", "Unknown")
                analytics_data.append({
                    "location": location_name,
                    "aqi": aqi_value,
                    "category": category
                })
        except:
            continue
    
    return render_template("analytics.html", analytics_data=analytics_data)


@app.route("/settings")
@login_required
def settings():
    conn = sqlite3.connect(USER_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT email, name FROM users WHERE id = ?", (session["user_id"],))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        flash("User not found", "error")
        return redirect(url_for("dashboard"))
    
    user_data = {
        "email": user[0],
        "name": user[1]
    }
    
    return render_template("setting.html")

@app.route("/update_settings", methods=["POST"])
@login_required
def update_settings():
    new_name = request.form.get("name")
    email = request.form.get("email")
    
    if not new_name or not email:
        flash("Name and email are required", "error")
        return redirect(url_for("settings"))
    
    if not is_valid_email(email):
        flash("Invalid email format", "error")
        return redirect(url_for("settings"))
    
    # Check if email already exists (for other users)
    conn = sqlite3.connect(USER_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = ? AND id != ?", (email, session["user_id"]))
    existing_user = cursor.fetchone()
    
    if existing_user:
        conn.close()
        flash("Email already in use by another account", "error")
        return redirect(url_for("settings"))
    
    # Update user info
    cursor.execute("UPDATE users SET name = ?, email = ? WHERE id = ?", 
                  (new_name, email, session["user_id"]))
    conn.commit()
    conn.close()
    
    # Update session
    session["user_name"] = new_name
    session["user_email"] = email
    
    flash("Settings updated successfully", "success")
    return redirect(url_for("settings"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)

