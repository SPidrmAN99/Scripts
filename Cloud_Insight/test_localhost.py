from flask import Flask, request, render_template_string, redirect, url_for, render_template
import re
import csv
import os

app = Flask(__name__)

# Define Samplespace with space and 94 characters (indices 1 to 94)
Samplespace = ' abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=[]{}|;:,.<>? '
Samplespace_index = dict(zip(Samplespace, range(1, len(Samplespace))))
index_to_Samplespace = dict(zip(range(1, len(Samplespace)), Samplespace))
key_list = [5039, 3812, 3166, 4926, 3874, 4619, 1637, 7252, 4348, 3240]

CSV_FILE = 'users.csv'

# Create the CSV file if it does not exist
if not os.path.exists(CSV_FILE):
    try:
        with open('users.csv', mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Username', 'EncryptedPassword'])  # Header
    except PermissionError:
        print("Bruh. Permission denied. Fix the file or close Excel.")


# --- Password validation ---
def validate_password(password):
    if len(password) < 8 or len(password) > 16:
        return "Password must be 8–16 characters, containing at least one uppercase letter, one lowercase letter, one digit, and one special character."
    if not re.search(r"[A-Z]", password):
        return "Include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Include at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return "Include at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Include at least one special character."
    return None

# --- Encryption Functions ---
def string_to_index(pt):
    return [Samplespace_index[char] for char in pt]

def extend_key(key, length):
    return (key * (length // len(key) + 1))[:length]

def vigenere_encrypt(plain_text, key):
    pt_indices = string_to_index(plain_text)
    key_extended = extend_key(key, len(plain_text))
    key_indices = string_to_index(key_extended)
    cipher_indices = [(pt_idx + key_idx - 1) % (len(Samplespace) - 1) + 1 for pt_idx, key_idx in zip(pt_indices, key_indices)]
    return ''.join(index_to_Samplespace[idx] for idx in cipher_indices)

# --- Routes ---
@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        key_number = request.form.get('key_number')

        # Validation
        if not username or not password or not confirm_password or not key_number:
            return error_page("All fields are required!")

        if password != confirm_password:
            return error_page("Passwords do not match! 🚨")

        pwd_error = validate_password(password)
        if pwd_error:
            return error_page(f"{pwd_error} 🚨")

        # Create UID username
        uid_number = get_next_uid_number()
        final_username = f"UID{uid_number}{username}"

        # Encrypt password
        key = str(key_list[int(key_number) - 1])
        encrypted_password = vigenere_encrypt(password, key)

        # Store into CSV
        with open(CSV_FILE, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([final_username, encrypted_password])

        # Redirect to success page
        return redirect(url_for('account_created', username=final_username))

    return render_form()

@app.route('/account_created')
def account_created():
    username = request.args.get('username')
    return render_template('account_created.html', username=username)

# --- Helper Functions ---
def render_form():
    return render_template_string('''
        <h2>Create Account</h2>
        <form method="POST">
            <label>Username:</label><br>
            <input type="text" name="username" required><br><br>
            <label>Password:</label><br>
            <input type="password" name="password" required><br><br>
            <label>Confirm Password:</label><br>
            <input type="password" name="confirm_password" required><br><br>
            <label>Key Number:</label><br>
            <select name="key_number" required>
                <option value="">--Select--</option>
                {% for i in range(1, 11) %}
                    <option value="{{ i }}">{{ i }}</option>
                {% endfor %}
            </select><br><br>
            <input type="submit" value="Create Account">
        </form>
    ''', )

def error_page(message):
    return render_template_string('''
        <h2>Create Account</h2>
        <form method="POST">
            <label>Username:</label><br>
            <input type="text" name="username" required><br><br>
            <label>Password:</label><br>
            <input type="password" name="password" required><br><br>
            <label>Confirm Password:</label><br>
            <input type="password" name="confirm_password" required><br><br>
            <label>Key Number:</label><br>
            <select name="key_number" required>
                <option value="">--Select--</option>
                {% for i in range(1, 11) %}
                    <option value="{{ i }}">{{ i }}</option>
                {% endfor %}
            </select><br><br>
            <input type="submit" value="Create Account">
        </form>
        <p style="color:red;">{{ message }}</p>
    ''', message=message)


def get_next_uid_number():
    if not os.path.exists(CSV_FILE):
        return 1
    with open(CSV_FILE, mode='r') as file:
        reader = csv.reader(file)
        next(reader, None)  # skip header
        rows = list(reader)
        return len(rows) + 1

# --- Main ---
if __name__ == '__main__':
    app.run(debug=True)
