#create a CSV file for username and password and then search for the password using the username
import csv, getpass, os
os.system('cls')
file1 = open('C:\\Personal\\Varun\\Board\\Computer_Science\\Programs\\Scripts\\Boards\\user.csv', 'w', newline='')
userwriter = csv.writer(file1)
users = []
ans = 'y'
while ans.lower() == 'y':
    os.system('cls')
    user = []
    print('Enter the details of the user. Be careful while entering the Password, its not visible.')
    username = input('Enter the Username: ')
    check = False
    while check == False:
        password = getpass.getpass('Enter the Password: ')
        confirm_password = getpass.getpass('Confirm the Password: ')
        if password == confirm_password:
            check = True
        else:
            print('Passwords do not match. Please try again.')
    user.extend([username, password])
    users.append(user)
    ans = input('Do you want to enter another user? (y/n): ')
    while ans.lower() != 'y' and ans.lower() != 'n':
        print('Invalid input. Please enter y or n.')
        ans = input('Do you want to enter another user? (y/n): ')
while ans.lower() == 'n':
    input('Press any key to exit.')
    break
userwriter.writerows(users)
file1.close()
os.system('cls')
file2 = open('C:\\Personal\\Varun\\Board\\Computer_Science\\Programs\\Scripts\\Boards\\user.csv', 'r')
userreader = csv.reader(file2)
cursor = file2.tell()
ans2 = 'y'
while ans2.lower() == 'y':
    os.system('cls')
    print('Enter Credentials(case sensitive)')
    file2.seek(cursor)
    searchuser = input('Enter the Username: ')
    found = False
    for user in userreader:
        if user[0] == searchuser:
            print('User found.')
            print('Password:', user[1])
            found = True
            break
    if found == False:
        print('User not found.')
    ans2 = input('Do you want to search for another user? (y/n): ')
    while ans2.lower() != 'y' and ans2.lower() != 'n':
        print('Invalid input. Please enter y or n.')
        ans2 = input('Do you want to search for another user? (y/n): ')
while ans2.lower() == 'n':
    input('Press any key to exit.')
    file2.close()
    break