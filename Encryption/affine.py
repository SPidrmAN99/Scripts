import os
import numpy as np
from egcd import egcd

os.system('cls')

# Define Samplespace with space and 94 characters (indices 1 to 94)
Samplespace = ' abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=[]{}|;:,.<>? '
Samplespace_index = dict(zip(Samplespace, range(1, len(Samplespace))))
index_to_Samplespace = dict(zip(range(1, len(Samplespace)), Samplespace))

# Get inputs
plain_text = input('Enter plain text: ')
a = input('Enter key "a" (must be coprime with 94): ')
b = input('Enter key "b" (any number): ')

# Validate "a" to be coprime with 94
while not a.isdigit() or egcd(int(a), len(Samplespace) - 1)[0] != 1:
    print('Key "a" must be a number and coprime with 94.')
    a = input('Enter key "a" (must be coprime with 94): ')
    
# Validate "b" to be a number
while not b.isdigit():
    print('Key "b" must be a number.')
    b = input('Enter key "b" (any number): ')

a = int(a)
b = int(b)

# Function to convert string to list of indices
def string_to_index(pt):
    return [Samplespace_index[char] for char in pt]

# Affine encryption function
def affine_encrypt(plain_text, a, b):
    pt_indices = string_to_index(plain_text)
    cipher_indices = [(a * idx + b - 1) % (len(Samplespace) - 1) + 1 for idx in pt_indices]
    return ''.join(index_to_Samplespace[idx] for idx in cipher_indices)

# Encrypt
cipher_text = affine_encrypt(plain_text, a, b)

# Output results
print(f"Plain text: {plain_text}")
print(f"Key (a, b): ({a}, {b})")
print(f"Cipher text: {cipher_text}")
