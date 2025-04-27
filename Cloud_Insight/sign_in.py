from flask import Flask, render_template, request
import csv

app = Flask(__name__)

# Key list and CSV file path
key_list = ["key1", "key2", "key3", "key4", "key5", "key6", "key7", "key8", "key9", "key10"]
CSV_FILE = 'users.csv'  # The CSV file storing username and encrypted password

def vigenere_encrypt(plain_text, key):
    # Vigenere encryption function
    encrypted_text = []
    key_index = 0
    for char in plain_text:
        key_char = key[key_index % len(key)]
        encrypted_char = chr(((ord(char) - 65) + (ord(key_char) - 65)) % 26 + 65)
        encrypted_text.append(encrypted_char)
        key_index += 1
    return ''.join(encrypted_text)

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ''  # Default message is empty
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        key_number = request.form['key_number']

        # Ensure a key_number is provided
        if not key_number:
            message = "Please select a Key Number."
            return render_template('login.html', message=message)

        key = str(key_list[int(key_number) - 1])

        # Read users from CSV
        with open(CSV_FILE, mode='r') as file:
            reader = csv.reader(file)
            next(reader)  # Skip header row
            users = list(reader)

        # Encrypt the entered password
        encrypted_password = vigenere_encrypt(password, key)

        # Check if username exists and the encrypted password matches
        for user in users:
            stored_username, stored_encrypted_password = user
            if stored_username == username:
                if stored_encrypted_password == encrypted_password:
                    message = "Login Successful! 🎉 Welcome to Cloud Insight."
                    return render_template('login.html', message=message)

        message = "Username not found. Try again. 🚨"
        return render_template('login.html', message=message)

    return render_template('login.html', message=message)

if __name__ == '__main__':
    app.run(debug=True)
