import os
import numpy as np
import random
from egcd import egcd
os.system('cls')
'''
alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

letter_to_index = dict(zip(alphabet, range(len(alphabet))))
index_to_letter = dict(zip(range(len(alphabet)), alphabet))'''

######################################################################################################################
### Samplespace
Samplespace = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=[]{}|;:,.<>? '
Samplespace_index = dict(zip(Samplespace, range(len(Samplespace))))
index_to_Samplespace = dict(zip(range(len(Samplespace)), Samplespace))

######################################################################################################################

def matrix_array(s, size):
    return [s[i:i+size] for i in range(0, len(s), size)]

######################################################################################################################
### Key Generation

key_ord = (input('enter sqare matrix key order: '))
while key_ord.isalpha():  # Loop while input is alphabetic
    print('Please enter a number')
    key_ord = input('Enter square matrix key order: ') 
key_ord = int(key_ord)
key_list = []
key = []
for index in range(key_ord*key_ord):
    key.append((input('Enter numbers of the key matrix row by row: ')))
    while key[index].isalpha():  # Loop while input is alphabetic
        print('Please enter a number')
        key.append(input('Enter numbers of the key matrix row by row: '))
for i in key:
    key_list.append(int(i))
#key_list = int(key_list)

key_matrix = np.array(matrix_array(key_list, key_ord))
print(key_matrix)

######################################################################################################################

pt = input('enter plain text:')#Hello there! General Kenobi!!
if len(pt)%key_ord > 0:
    while len(pt) % key_ord > 0:
        random_letter = random.choice(Samplespace)
        pt += random_letter
print(pt)

def string_to_index(pt):  
    return [Samplespace_index[char] for char in pt]
pt_index = string_to_index(pt)
print(pt_index)
P = []



pt_matrix = np.array([matrix_array(pt_index, key_ord)])
print(pt_matrix)





message_vectors = pt_matrix.reshape(-1, key_ord).T
print (pt_matrix)
print(message_vectors)

#key_list = []

'''
for index in range(key_ord*key_ord):
    key_list.append(int(input('Enter numbers of the key matrix row by row: ')))
'''
key_matrix = matrix_array(key_list, key_ord)

key_matrix = np.array(key_matrix)


# Encrypt using the Hill cipher formula: C = (K * P) mod 256
cipher_matrix_vectors = (np.dot(key_matrix, message_vectors) % 89)

# Convert the ciphertext back to the original shape
cipher_matrix_vectors = cipher_matrix_vectors.T
cipher_matrix_vectors = cipher_matrix_vectors.tolist()
print(cipher_matrix_vectors)

cipher_list = []

for partial_cipher in cipher_matrix_vectors:
    cipher_list.extend(partial_cipher)
#ct = ascii_to_string(cipher_list)
cipher_text_list = []

for i in range(len(cipher_list)):
    cipher_text_list.append(index_to_Samplespace[cipher_list[i]])
    cipher_text = ''.join(cipher_text_list)

print('Key: ', key_matrix)
print('Plain text: ',pt)
print ('Cipher Text: ' , cipher_text)

'''def string_to_ascii(pt):
    return [ord(char) for char in pt]

def ascii_to_string(ascii_list):
    return ''.join(chr(num) for num in ascii_list)

key_ord = (input('enter sqare matrix key order: '))
pt = input('enter plain text:')#Hello there! General Kenobi!!

if len(pt)%key_ord > 0:
    while len(pt) % key_ord > 0:
        random_letter = random.choice(Samplespace)
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
'''