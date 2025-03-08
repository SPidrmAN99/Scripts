import os
import numpy as np
import random
from egcd import egcd
os.system('cls')

alphabet = 'abcdefghijklmnopqrstuvwxyz'
cap_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

small_letter_to_index = dict(zip(alphabet, range(len(alphabet))))
index_to_small_letter = dict(zip(range(len(alphabet)), alphabet))

cap_letter_to_index = dict(zip(cap_alphabet, range(26,26+len(cap_alphabet))))
index_to_cap_letter = dict(zip(range(26,26+len(cap_alphabet)), cap_alphabet))

index_to_letter = {**small_letter_to_index, **cap_letter_to_index}#key: letters
letter_to_index = {**index_to_small_letter, **index_to_cap_letter}#key: alphabets


def string_to_ascii(pt):
    return [ord(char) for char in pt]

def ascii_to_string(ascii_list):
    return ''.join(chr(num) for num in ascii_list)

key_ord = int(input('enter sqare matrix key order: '))
pt = input('enter plain text:')#Hello there! General Kenobi!!

if len(pt)%key_ord > 0:
    while len(pt) % key_ord > 0:
        random_letter = random.choice(alphabet + cap_alphabet)
        pt += random_letter

pt_ascii = string_to_ascii(pt)

def matrix_array(s, size):
    return [s[i:i+size] for i in range(0, len(s), size)]

pt_matrix = matrix_array(pt, key_ord)
print(pt_matrix)
pt_ascii_matrix = []
for chunk in pt_matrix:
    pt_ascii_matrix.append(string_to_ascii(chunk))
    
pt_ascii_matrix = np.array([pt_ascii_matrix])
message_vectors = pt_ascii_matrix.reshape(-1, key_ord).T
print (pt_ascii_matrix)
print(message_vectors)

key_list = []

for index in range(key_ord*key_ord):
    key_list.append(int(input('Enter numbers of the key matrix row by row: ')))

key_matrix = matrix_array(key_list, key_ord)

key_matrix = np.array(key_matrix)


# Encrypt using the Hill cipher formula: C = (K * P) mod 256
cipher_matrix_vectors = (np.dot(key_matrix, message_vectors) % 128)

# Convert the ciphertext back to the original shape
cipher_matrix_vectors = cipher_matrix_vectors.T
cipher_matrix_vectors = cipher_matrix_vectors.tolist()
print(cipher_matrix_vectors)

cipher_list = []

for partial_cipher in cipher_matrix_vectors:
    cipher_list.extend(partial_cipher)
ct = ascii_to_string(cipher_list)

print('Key: ', key_matrix)
print('Plain text: ',pt)
print ('Cipher Text: ' , ct)
#T.4dEc|t/]co4☻%/];Ud:%]g▼