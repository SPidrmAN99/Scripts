from flask import Flask, render_template, request, redirect, url_for, session
import csv
import os
import bcrypt # Import bcrypt for password hashing

app = Flask(__name__)
# Set a secret key for sessions. THIS MUST BE A LONG, RANDOM STRING IN PRODUCTION.
app.secret_key = 'another_super_secret_key_for_sign_in_app_change_this' 

# CSV file path (MUST be consistent with deployment_v1.py)
CSV_FILE = 'users.csv'

# --- Root Route for sign_in.py (New addition) ---
@app.route('/')
def index_login():
    """
    Redirects to the /login route or renders the login page directly.
    This serves as the entry point for the sign_in application.
    """
    return redirect(url_for('login'))
    # Alternatively, to render directly: return render_template('login.html', message='')

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ''  # Default message is empty
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Input validation
        if not all([username, password]):
            message = "All fields are required."
            return render_template('login.html', message=message)

        # Read users from CSV
        users = []
        if os.path.exists(CSV_FILE):
            try:
                with open(CSV_FILE, mode='r', newline='') as file:
                    reader = csv.reader(file)
                    header = next(reader, None) # Skip header
                    if header != ['Username', 'HashedPassword']:
                         print(f"WARNING: CSV header mismatch. Expected ['Username', 'HashedPassword'], got {header}. Attempting to proceed.")
                    users = list(reader)
            except Exception as e:
                print(f"ERROR: Failed to read from CSV file: {e}")
                message = "An error occurred while accessing user data."
                return render_template('login.html', message=message)
        else:
            message = "No user accounts found. Please create an account first."
            return render_template('login.html', message=message)

        user_found = False
        for user_data in users:
            if len(user_data) == 2:
                stored_username, stored_hashed_password_str = user_data
                if stored_username == username:
                    user_found = True
                    # Check the entered password against the stored hash
                    if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password_str.encode('utf-8')):
                        # --- SUCCESSFUL LOGIN REDIRECT ---
                        session['username'] = username # Store username in session
                        print(f"INFO: Login successful for {username}. Redirecting to dashboard.")
                        return redirect(url_for('dashboard', username=username)) # Redirect to dashboard
                    else:
                        message = "Incorrect password. Try again. 🚨"
                        return render_template('login.html', message=message)
            else:
                print(f"WARNING: Malformed row in CSV: {user_data}")

        if not user_found:
            message = "Username not found. Try again. 🚨"
        
    return render_template('login.html', message=message)

# --- Dashboard Route ---
@app.route('/dashboard')
def dashboard():
    """
    Displays the user dashboard after successful login.
    Checks session for login state.
    """
    # Check if user is logged in via session
    if 'username' in session:
        username = session['username'] # Get username from session
        return render_template('dashboard.html', username=username)
    else:
        # If not logged in, redirect to login page with a message
        return redirect(url_for('login', message="Please log in to access the dashboard."))


# --- Main Entry Point ---
if __name__ == '__main__':
    # IMPORTANT: Set debug=False in a production environment!
    app.run(debug=True, port=5001) # Ensure it runs on port 5001