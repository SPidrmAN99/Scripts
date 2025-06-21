from flask import Flask, request, render_template, redirect, url_for, session
import re
import csv
import os
import bcrypt # Import bcrypt for password hashing

app = Flask(__name__)
# For sessions (needed for real login state), set a secret key
app.secret_key = 'your_super_secret_key_here_please_change_this_in_production' 

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
        # Get the next available UID based on existing users.
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

# --- Login Routes and Logic ---
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
                        # Store username in session (basic login state)
                        session['username'] = username 
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
    Requires user to be logged in (check session).
    """
    # In a real app, you would check if session['username'] exists.
    # For simplicity, we are passing username via URL args for now.
    username = request.args.get('username', 'Guest') # Default to Guest if not passed
    if 'username' in session and session['username'] == username: # Check if logged in user matches URL user
        return render_template('dashboard.html', username=username)
    elif 'username' in session: # If a user is logged in, but tried to access another user's dashboard
        return render_template('dashboard.html', username=session['username'], message="Logged in as a different user.")
    else: # Not logged in
        return redirect(url_for('login', message="Please log in to access the dashboard."))


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
        # Read all rows, skipping the header.
        rows = list(reader)
        # Adjusted logic to correctly count users after potentially skipping header
        if len(rows) > 0 and rows[0] == ['Username', 'HashedPassword']:
            return len(rows) # If header is present, count is total rows
        else:
            return len(rows) + 1 # If no header (empty or malformed), start from 1 + existing rows


# --- Main Entry Point ---
if __name__ == '__main__':
    # IMPORTANT: Set debug=False in a production environment!
    # debug=True exposes sensitive information and should only be used for local development.
    app.run(debug=True)
