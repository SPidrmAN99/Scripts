Cloud Insight User Management Application

This document provides the complete, working code for your Flask-based user management system. It's designed as two separate, inter-communicating Flask applications, reflecting your preference for separate scripts.
Project Overview

    deployment_v1.py: Handles user account creation. It runs on http://127.0.0.1:5000/.

    sign_in.py: Handles user login and provides a simple dashboard for authenticated users. It runs on http://127.0.0.1:5001/.

    users.csv: A CSV file used for storing user data (username and bcrypt-hashed password).

    templates/: Contains all HTML files, styled with a custom "Orange Business" theme using Tailwind CSS.

    Security: Passwords are securely hashed using bcrypt.

File Structure

Your project directory should be organized exactly like this:

your_project_folder/
├── deployment_v1.py         # Account Creation Flask App
├── sign_in.py               # Login & Dashboard Flask App
├── users.csv                # Stores user data (created automatically if not present)
├── requirements.txt         # Lists Python dependencies
└── templates/
    ├── index.html           # Account Creation Form (served by deployment_v1.py)
    ├── account_created.html # Account Creation Success Page (served by deployment_v1.py)
    ├── error.html           # Generic Error Page for Account Creation (served by deployment_v1.py)
    ├── login.html           # Login Form (served by sign_in.py)
    └── dashboard.html       # User Dashboard (served by sign_in.py)

Python Scripts
1. deployment_v1.py (Account Creation Application)

This script manages user registration.

from flask import Flask, request, render_template, redirect, url_for
import re
import csv
import os
import bcrypt # Import bcrypt for password hashing

app = Flask(__name__)
# No session needed here as it's just for account creation, no login state maintained.

# --- IMPORTANT DEPLOYMENT CHANGE: Relative path for CSV file ---
# This path is relative to the directory where your Flask app is run from.
# WARNING: Storing user data directly in a CSV file on the web server's filesystem
# is NOT suitable for production. Data may be lost on app restarts/scaling,
# and it's not concurrent-safe. For a real application, use a proper database (e.g., Azure SQL, Cosmos DB).
CSV_FILE = 'users.csv'

# Create the CSV file if it does not exist
if not os.path.exists(CSV_FILE):
    try:
        with open(CSV_FILE, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Username', 'HashedPassword']) # Changed header to HashedPassword
        print(f"INFO: Created new CSV file at {CSV_FILE}")
    except PermissionError:
        print(f"ERROR: Permission denied when trying to create/write to {CSV_FILE}. "
              "Please check file permissions or ensure the file is not open elsewhere.")
    except Exception as e:
        print(f"ERROR: An unexpected error occurred while managing {CSV_FILE}: {e}")

# --- Password validation ---
def validate_password(password):
    """
    Validates the given password against a set of criteria.

    Args:
        password (str): The password string to validate.

    Returns:
        str or None: An error message if validation fails, otherwise None.
    """
    if not (8 <= len(password) <= 16):
        return "Password must be 8–16 characters."
    if not re.search(r"[A-Z]", password):
        return "Include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Include at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return "Include at least one digit."
    # Regex for special characters (consistent with common practices)
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Include at least one special character."
    return None

# --- Account Creation Routes and Logic ---
@app.route('/', methods=['GET', 'POST'])
def home():
    """
    Handles the account creation form, including validation, password hashing,
    and storage of user data.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # --- Input Validation ---
        if not all([username, password, confirm_password]):
            return render_template('error.html', message="All fields are required! 🚨")

        if password != confirm_password:
            return render_template('error.html', message="Passwords do not match! 🚨")

        pwd_error = validate_password(password)
        if pwd_error:
            return render_template('error.html', message=f"{pwd_error} 🚨")
        
        # --- Generate UID and Hash Password ---
        uid_number = get_next_uid_number()
        final_username = f"UID{uid_number}{username}"

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        hashed_password_str = hashed_password.decode('utf-8') # Store as string

        # --- Store User Data to CSV ---
        try:
            with open(CSV_FILE, mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([final_username, hashed_password_str])
            print(f"INFO: Account for {final_username} created and saved.")
        except IOError as e:
            print(f"ERROR: Failed to write user data to CSV: {e}")
            return render_template('error.html', message="Failed to save account. Please try again. 🚨")
        except Exception as e:
            print(f"ERROR: An unexpected error occurred during CSV write: {e}")
            return render_template('error.html', message="An unexpected error occurred. Please try again. 🚨")

        # Redirect to a success page, passing only username
        return redirect(url_for('account_created', username=final_username))

    # For GET requests, render the account creation form
    return render_template('index.html')

@app.route('/account_created')
def account_created():
    """
    Displays the account creation success page.
    """
    username = request.args.get('username')
    return render_template('account_created.html', username=username)


# --- Helper Function for UID Generation ---
def get_next_uid_number():
    """
    Determines the next sequential User ID number based on the existing entries in the CSV.
    This method is prone to issues with concurrency and deleted rows in a multi-user environment.
    """
    if not os.path.exists(CSV_FILE):
        return 1
    with open(CSV_FILE, mode='r', newline='') as file:
        reader = csv.reader(file)
        rows = list(reader)
        if len(rows) > 0 and rows[0] == ['Username', 'HashedPassword']:
            return len(rows)
        else:
            return len(rows) + 1


# --- Main Entry Point ---
if __name__ == '__main__':
    # IMPORTANT: Set debug=False in a production environment!
    app.run(debug=True, port=5000) # Ensure it runs on port 5000

2. sign_in.py (Login & Dashboard Application)

This script handles user login and the dashboard.

from flask import Flask, render_template, request, redirect, url_for, session
import csv
import os
import bcrypt # Import bcrypt for password hashing

app = Flask(__name__)
# Set a secret key for sessions. THIS MUST BE A LONG, RANDOM STRING IN PRODUCTION.
app.secret_key = 'another_super_secret_key_for_sign_in_app_change_this' 

# CSV file path (MUST be consistent with deployment_v1.py)
CSV_FILE = 'users.csv'

# --- Root Route for sign_in.py ---
@app.route('/')
def index_login():
    """
    Redirects to the /login route. This serves as the entry point for the sign_in application.
    """
    return redirect(url_for('login'))

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

HTML Templates (Place these in the templates/ folder)
1. templates/index.html (Account Creation Form)

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Account - Cloud Insight</title>
    <!-- Tailwind CSS for modern styling -->
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        /* Custom font for better aesthetics */
        body {
            font-family: "Inter", sans-serif;
        }
        /* Orange Business color palette */
        .bg-orange-business-dark { background-color: #FF7900; }
        .bg-orange-business-light { background-color: #FFB366; }
        .text-orange-business { color: #FF7900; }
        .border-orange-business { border-color: #FF7900; }
        .bg-gray-business-dark { background-color: #333333; }
        .text-gray-business { color: #333333; }
        .hover-bg-orange-business:hover { background-color: #E66A00; }
        .hover-text-orange-business:hover { color: #E66A00; }

        .password-message-error {
            color: #ef4444; /* red-500 */
            font-size: 0.875rem; /* text-sm */
            margin-top: 0.25rem;
        }
        .password-message-success {
            color: #22c55e; /* green-500 */
            font-size: 0.875rem; /* text-sm */
            margin-top: 0.25rem;
        }
    </style>
</head>
<body class="bg-gradient-to-r from-orange-business-light to-orange-business-dark flex items-center justify-center min-h-screen p-4">
    <div class="bg-white p-8 rounded-2xl shadow-xl w-full max-w-md border-t-4 border-orange-business">
        <h2 class="text-3xl font-extrabold mb-7 text-center text-gray-business">Create Your Account</h2>
        <form method="POST" action="/" class="space-y-6" id="createAccountForm">
            <div>
                <label for="username" class="block text-sm font-semibold text-gray-700 mb-1">Username:</label>
                <input type="text" id="username" name="username" required
                       class="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:ring-orange-business focus:border-orange-business text-gray-900 placeholder-gray-400"
                       placeholder="Enter your desired username">
            </div>
            <div>
                <label for="password" class="block text-sm font-semibold text-gray-700 mb-1">Password:</label>
                <input type="password" id="password" name="password" required
                       class="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:ring-orange-business focus:border-orange-business text-gray-900 placeholder-gray-400"
                       placeholder="Enter your password">
                <p id="password_message" class="text-xs mt-2"></p> <!-- Message area for JS validation -->
            </div>
            <div>
                <label for="confirm_password" class="block text-sm font-semibold text-gray-700 mb-1">Confirm Password:</label>
                <input type="password" id="confirm_password" name="confirm_password" required
                       class="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:ring-orange-business focus:border-orange-business text-gray-900 placeholder-gray-400"
                       placeholder="Confirm your password">
            </div>
            <button type="submit"
                    class="w-full flex justify-center py-3 px-4 border border-transparent rounded-lg shadow-md text-base font-bold text-white bg-orange-business-dark hover-bg-orange-business focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-business transform transition-transform duration-150 ease-in-out hover:scale-105">
                Create Account
            </button>
            <p class="mt-4 text-center text-sm text-gray-600">
                Already have an account? <a href="http://127.0.0.1:5001/login" class="font-medium text-orange-business hover-text-orange-business">Sign In</a>
            </p>
        </form>
    </div>

    <script>
        document.addEventListener("DOMContentLoaded", () => {
            const passwordInput = document.getElementById("password");
            const confirmPasswordInput = document.getElementById("confirm_password");
            const passwordMessage = document.getElementById("password_message");
            const form = document.getElementById("createAccountForm");

            function validatePasswordFields() {
                const pwd = passwordInput.value;
                const confirmPwd = confirmPasswordInput.value;
                let errors = [];

                if (pwd.length < 8 || pwd.length > 16) {
                    errors.push("Password must be 8–16 characters.");
                }
                if (!/[a-z]/.test(pwd)) {
                    errors.push("Include at least one lowercase letter.");
                }
                if (!/[A-Z]/.test(pwd)) {
                    errors.push("Include at least one uppercase letter.");
                }
                if (!/[0-9]/.test(pwd)) {
                    errors.push("Include at least one digit.");
                }
                if (!/[!@#$%^&*(),.?\":{}|<>]/.test(pwd)) {
                    errors.push("Include at least one special character.");
                }

                if (pwd !== confirmPwd && confirmPwd.value.length > 0) {
                    errors.push("Passwords do not match.");
                }

                if (errors.length > 0) {
                    passwordMessage.className = "password-message-error";
                    passwordMessage.innerHTML = errors.join("<br>");
                    return false;
                } else {
                    passwordMessage.className = "password-message-success";
                    passwordMessage.innerHTML = "✅ Password looks good!";
                    return true;
                }
            }

            passwordInput.addEventListener("input", validatePasswordFields);
            confirmPasswordInput.addEventListener("input", validatePasswordFields);
            validatePasswordFields();
        });
    </script>
</body>
</html>

2. templates/account_created.html (Account Creation Success Page)

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Account Created - Cloud Insight</title>
    <!-- Tailwind CSS for modern styling -->
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        /* Custom font for better aesthetics */
        body {
            font-family: "Inter", sans-serif;
        }
        /* Orange Business color palette */
        .bg-orange-business-dark { background-color: #FF7900; }
        .bg-orange-business-light { background-color: #FFB366; }
        .text-orange-business { color: #FF7900; }
        .border-orange-business { border-color: #FF7900; }
        .bg-gray-business-dark { background-color: #333333; }
        .text-gray-business { color: #333333; }
        .hover-bg-orange-business:hover { background-color: #E66A00; }
        .hover-text-orange-business:hover { color: #E66A00; }
    </style>
</head>
<body class="bg-gradient-to-br from-orange-business-light to-orange-business-dark flex items-center justify-center min-h-screen p-4">
    <div class="bg-white p-8 rounded-2xl shadow-xl w-full max-w-md text-center border-t-4 border-orange-business">
        <h2 class="text-3xl font-extrabold mb-6 text-orange-business">Account Created Successfully! 🎉</h2>
        <p class="text-gray-700 text-lg mb-3">Your new username is: <br><strong class="font-bold text-gray-business text-xl">{{ username }}</strong></p>
        <p class="text-gray-600 text-sm italic mb-8">Please note down your username. It's different from the one you entered!</p>
        <div class="flex flex-col space-y-4 sm:flex-row sm:space-y-0 sm:space-x-4 justify-center">
            <a href="/"
               class="inline-block bg-orange-business-dark hover-bg-orange-business text-white font-bold py-3 px-6 rounded-lg shadow-lg transition-transform duration-150 ease-in-out hover:scale-105 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-business">
                Create another account
            </a>
            <a href="http://127.0.0.1:5001/login"
               class="inline-block bg-gray-business-dark hover:bg-gray-700 text-white font-bold py-3 px-6 rounded-lg shadow-lg transition-transform duration-150 ease-in-out hover:scale-105 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-business">
                Sign In
            </a>
        </div>
    </div>
</body>
</html>

3. templates/error.html (Account Creation Error Page)

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - Cloud Insight</title>
    <!-- Tailwind CSS for modern styling -->
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        /* Custom font for better aesthetics */
        body {
            font-family: "Inter", sans-serif;
        }
        /* Orange Business color palette */
        .bg-orange-business-dark { background-color: #FF7900; }
        .bg-orange-business-light { background-color: #FFB366; }
        .text-orange-business { color: #FF7900; }
        .border-orange-business { border-color: #FF7900; }
        .bg-gray-business-dark { background-color: #333333; }
        .text-gray-business { color: #333333; }
        .hover-bg-orange-business:hover { background-color: #E66A00; }
        .hover-text-orange-business:hover { color: #E66A00; }

        .password-message-error {
            color: #ef4444; /* red-500 */
            font-size: 0.875rem; /* text-sm */
            margin-top: 0.25rem;
        }
        .password-message-success {
            color: #22c55e; /* green-500 */
            font-size: 0.875rem; /* text-sm */
            margin-top: 0.25rem;
        }
    </style>
</head>
<body class="bg-gradient-to-r from-orange-business-light to-orange-business-dark flex items-center justify-center min-h-screen p-4">
    <div class="bg-white p-8 rounded-2xl shadow-xl w-full max-w-md border-t-4 border-red-700">
        <h2 class="text-3xl font-extrabold mb-6 text-center text-red-600">Account Creation Failed! 🚨</h2>
        <p class="text-red-500 text-center text-lg mb-6 font-medium">{{ message }}</p>
        
        <!-- Re-display the form so the user can try again -->
        <form method="POST" action="/" class="space-y-6" id="createAccountForm">
            <div>
                <label for="username" class="block text-sm font-semibold text-gray-700 mb-1">Username:</label>
                <input type="text" id="username" name="username" required
                       class="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:ring-orange-business focus:border-orange-business text-gray-900 placeholder-gray-400"
                       placeholder="Enter your desired username">
            </div>
            <div>
                <label for="password" class="block text-sm font-semibold text-gray-700 mb-1">Password:</label>
                <input type="password" id="password" name="password" required
                       class="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:ring-orange-business focus:border-orange-business text-gray-900 placeholder-gray-400"
                       placeholder="Enter your password">
                <p id="password_message" class="text-xs mt-2"></p> <!-- Message area for JS validation -->
            </div>
            <div>
                <label for="confirm_password" class="block text-sm font-semibold text-gray-700 mb-1">Confirm Password:</label>
                <input type="password" id="confirm_password" name="confirm_password" required
                       class="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:ring-orange-business focus:border-orange-business text-gray-900 placeholder-gray-400"
                       placeholder="Confirm your password">
            </div>
            <button type="submit"
                    class="w-full flex justify-center py-3 px-4 border border-transparent rounded-lg shadow-md text-base font-bold text-white bg-orange-business-dark hover-bg-orange-business focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-business transform transition-transform duration-150 ease-in-out hover:scale-105">
                Try Again
            </button>
            <p class="mt-4 text-center text-sm text-gray-600">
                Already have an account? <a href="http://127.0.0.1:5001/login" class="font-medium text-orange-business hover-text-orange-business">Sign In</a>
            </p>
        </form>
    </div>

    <script>
        // Client-side validation script (copy of index.html's script for consistency)
        document.addEventListener("DOMContentLoaded", () => {
            const passwordInput = document.getElementById("password");
            const confirmPasswordInput = document.getElementById("confirm_password");
            const passwordMessage = document.getElementById("password_message");
            const form = document.getElementById("createAccountForm");

            function validatePasswordFields() {
                const pwd = passwordInput.value;
                const confirmPwd = confirmPasswordInput.value;
                let errors = [];

                if (pwd.length < 8 || pwd.length > 16) {
                    errors.push("Password must be 8–16 characters.");
                }
                if (!/[a-z]/.test(pwd)) {
                    errors.push("Include at least one lowercase letter.");
                }
                if (!/[A-Z]/.test(pwd)) {
                    errors.push("Include at least one uppercase letter.");
                }
                if (!/[0-9]/.test(pwd)) {
                    errors.push("Include at least one digit.");
                }
                if (!/[!@#$%^&*(),.?\":{}|<>]/.test(pwd)) {
                    errors.push("Include at least one special character.");
                }

                if (pwd !== confirmPwd && confirmPwd.value.length > 0) {
                    errors.push("Passwords do not match.");
                }

                if (errors.length > 0) {
                    passwordMessage.className = "password-message-error";
                    passwordMessage.innerHTML = errors.join("<br>");
                    return false;
                } else {
                    passwordMessage.className = "password-message-success";
                    passwordMessage.innerHTML = "✅ Password looks good!";
                    return true;
                }
            }

            passwordInput.addEventListener("input", validatePasswordFields);
            confirmPasswordInput.addEventListener("input", validatePasswordFields);
            validatePasswordFields(); // Initial check
        });
    </script>
</body>
</html>

4. templates/login.html (Login Form)

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Cloud Insight</title>
    <!-- Tailwind CSS for modern styling -->
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        /* Custom font for better aesthetics */
        body {
            font-family: "Inter", sans-serif;
        }
        /* Orange Business color palette */
        .bg-orange-business-dark { background-color: #FF7900; }
        .bg-orange-business-light { background-color: #FFB366; }
        .text-orange-business { color: #FF7900; }
        .border-orange-business { border-color: #FF7900; }
        .bg-gray-business-dark { background-color: #333333; }
        .text-gray-business { color: #333333; }
        .hover-bg-orange-business:hover { background-color: #E66A00; }
        .hover-text-orange-business:hover { color: #E66A00; }

        .message-error {
            color: #ef4444; /* red-500 */
            font-weight: bold;
            text-align: center;
            margin-top: 1rem;
        }
        .message-success {
            color: #22c55e; /* green-500 */
            font-weight: bold;
            text-align: center;
            margin-top: 1rem;
        }
    </style>
</head>
<body class="bg-gradient-to-r from-orange-business-light to-orange-business-dark flex items-center justify-center min-h-screen p-4">
    <div class="bg-white p-8 rounded-2xl shadow-xl w-full max-w-md border-t-4 border-orange-business">
        <h2 class="text-3xl font-extrabold mb-7 text-center text-gray-business">Sign In</h2>
        <form method="POST" action="/login" class="space-y-6">
            <div>
                <label for="username" class="block text-sm font-semibold text-gray-700 mb-1">Username:</label>
                <input type="text" id="username" name="username" required
                       class="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:ring-orange-business focus:border-orange-business text-gray-900 placeholder-gray-400"
                       placeholder="Your username">
            </div>
            <div>
                <label for="password" class="block text-sm font-semibold text-gray-700 mb-1">Password:</label>
                <input type="password" id="password" name="password" required
                       class="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:ring-orange-business focus:border-orange-business text-gray-900 placeholder-gray-400"
                       placeholder="Your password">
            </div>
            <button type="submit"
                    class="w-full flex justify-center py-3 px-4 border border-transparent rounded-lg shadow-md text-base font-bold text-white bg-orange-business-dark hover-bg-orange-business focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-business transform transition-transform duration-150 ease-in-out hover:scale-105">
                Sign In
            </button>
            <p class="mt-4 text-center text-sm text-gray-600">
                Don't have an account? <a href="http://127.0.0.1:5000/" class="font-medium text-orange-business hover-text-orange-business">Create Account</a>
            </p>
        </form>

        <!-- Display the message dynamically -->
        {% if message %}
            <p class="{% if 'Successful' in message %}message-success{% else %}message-error{% endif %}">
                {{ message }}
            </p>
        {% endif %}
    </div>
</body>
</html>

5. templates/dashboard.html (User Dashboard)

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud Insight Dashboard</title>
    <!-- Tailwind CSS for modern styling -->
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        /* Custom font for better aesthetics */
        body {
            font-family: "Inter", sans-serif;
        }
        /* Orange Business color palette */
        .bg-orange-business-dark { background-color: #FF7900; }
        .bg-orange-business-light { background-color: #FFB366; }
        .text-orange-business { color: #FF7900; }
        .border-orange-business { border-color: #FF7900; }
        .bg-gray-business-dark { background-color: #333333; }
        .text-gray-business { color: #333333; }
        .hover-bg-orange-business:hover { background-color: #E66A00; }
        .hover-text-orange-business:hover { color: #E66A00; }
    </style>
</head>
<body class="bg-gradient-to-br from-orange-business-light to-orange-business-dark flex items-center justify-center min-h-screen p-4">
    <div class="bg-white p-8 rounded-2xl shadow-xl w-full max-w-2xl border-t-4 border-orange-business">
        <h1 class="text-4xl font-extrabold mb-6 text-center text-gray-business">Welcome to Cloud Insight Dashboard!</h1>
        <p class="text-lg text-gray-700 text-center mb-8">Hello, <strong class="text-orange-business">{{ username }}</strong>! You have successfully logged in.</p>
        <div class="flex flex-col space-y-4 items-center">
            <a href="http://127.0.0.1:5000/"
               class="inline-block bg-orange-business-dark hover-bg-orange-business text-white font-bold py-3 px-8 rounded-lg shadow-lg transition-transform duration-150 ease-in-out hover:scale-105 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-business">
                Go to Account Creation
            </a>
            <a href="/login"
               class="inline-block bg-gray-business-dark hover:bg-gray-700 text-white font-bold py-3 px-8 rounded-lg shadow-lg transition-transform duration-150 ease-in-out hover:scale-105 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-business">
                Logout (back to Login)
            </a>
        </div>
    </div>
</body>
</html>

Other Files
users.csv

Create an empty file named users.csv in the root of your project directory. The deployment_v1.py script will automatically add the header and user data to it.
requirements.txt

Create a file named requirements.txt in the root of your project directory with the following content:

Flask==2.3.2 # Or your specific Flask version
bcrypt

How to Run Your Applications Locally

Since you prefer separate scripts, you will need to run each Flask application in its own terminal window.

    Open your first terminal/command prompt.

    Navigate to your project's root directory (e.g., cd C:\Users\YourUser\Documents\CLOUD_INSIGHT).

    Run the Account Creation App:

    python deployment_v1.py

    This app will run on http://127.0.0.1:5000/.

    Open a second terminal/command prompt window.

    Navigate to the same project's root directory.

    Run the Login & Dashboard App:

    python sign_in.py

    This app will run on http://127.0.0.1:5001/.

    Access your applications in your web browser:

        For Account Creation: Go to http://127.0.0.1:5000/

        For Login/Dashboard: Go to http://127.0.0.1:5001/

    You can navigate between them using the provided links in the HTML pages.

Deployment Considerations for Azure Web App

    File Paths: The CSV_FILE = 'users.csv' relative path will work on Azure.

    Data Persistence (CSV Warning!): As repeatedly warned, using a CSV file on the web server's filesystem for user data is not robust for production. Data can be lost on app restarts or scaling. For a real application, you MUST replace CSV with a proper database like Azure SQL Database, Azure Cosmos DB, or Azure Table Storage. This is the most significant upgrade for a production environment.

    Multiple Apps on Azure: Deploying two separate Flask apps (like deployment_v1.py and sign_in.py) to Azure typically means deploying them to two separate Azure App Services. Each App Service will have its own URL (e.g., app-create.azurewebsites.net and app-login.azurewebsites.net). You would then update the http://127.0.0.1:XXXX/ links in your HTML templates to point to these live Azure URLs.

    app.run(debug=True): Ensure debug=True is changed to debug=False for production deployments. Azure's web server (like Gunicorn) will manage starting your application.

    Secret Keys: The app.secret_key values ('your_super_secret_key_here_please_change_this_in_production' and 'another_super_secret_key_for_sign_in_app_change_this') are placeholders. In a production environment, these should be long, randomly generated strings stored securely as environment variables in Azure App Service Configuration, not hardcoded in your script.

You've done a great job getting your dual Flask application set up! These final code pieces should provide a clear and complete picture for your project.
