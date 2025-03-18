Samplespace = ' abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=[]{}|;:,.<>? '
Samplespace_index = dict(zip(Samplespace, range(1, len(Samplespace))))
index_to_Samplespace = dict(zip(range(1, len(Samplespace)), Samplespace))

plain_text = input('enter plain text: ')
key = input('Enter key (number only): ')
while not key.isdigit():
    print('Please enter a number')
    key = input('Enter key (number only): ')
key = int(key)

def string_to_index(pt):
    return [Samplespace_index[char] for char in pt]

def encrypt(plain_text, key):
    pt_indices = string_to_index(plain_text)
    cipher_indices = [(idx + key - 1) % (len(Samplespace) - 1) + 1 for idx in pt_indices]
    return ''.join(index_to_Samplespace[idx] for idx in cipher_indices)

cipher_text = encrypt(plain_text, key)
print(f"Plain text: {plain_text}")
print(f"Key (shift): {key}")
print(f"Cipher text: {cipher_text}")