# Define Samplespace with space and 94 characters (indices 1 to 94)
Samplespace = ' abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=[]{}|;:,.<>? '
Samplespace_index = dict(zip(Samplespace, range(1, len(Samplespace))))
index_to_Samplespace = dict(zip(range(1, len(Samplespace)), Samplespace))

# Get inputs
plain_text = input('enter plain text: ')
key = input('Enter key: ')

# Function to convert string to list of indices
def string_to_index(pt):
    return [Samplespace_index[char] for char in pt]

# Function to extend key to match plain text length
def extend_key(key, length):
    return (key * (length // len(key) + 1))[:length]

# XOR encryption with string key
def xor_encrypt(plain_text, key):
    pt_indices = string_to_index(plain_text)
    key_extended = extend_key(key, len(plain_text))  # Repeat key to match length
    key_indices = string_to_index(key_extended)      # Convert key to indices
    # XOR each plain text index with corresponding key index, wrap with modulo
    cipher_indices = [(pt_idx ^ key_idx) % (len(Samplespace) - 1) + 1 for pt_idx, key_idx in zip(pt_indices, key_indices)]
    return ''.join(index_to_Samplespace[idx] for idx in cipher_indices)

# Encrypt
cipher_text = xor_encrypt(plain_text, key)

# Output results
print(f"Plain text: {plain_text}")
print(f"Key: {key}")
print(f"Cipher text: {cipher_text}")