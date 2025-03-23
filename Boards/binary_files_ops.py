import pickle, os
os.system("cls")
file1 = open("Student_record.dat", "wb")
students = {34: 'Varun', 12: 'Rahul', 56: 'Rohit', 78: 'Rajesh'}
searchkeys = students.keys()
pickle.dump(students, file1)
file1.close()
ans = 'y'
while ans.lower() == 'y':
    key = int(input("Enter the roll number of the student: "))
    if key in searchkeys:
        file2 = open("Student_record.dat", "rb")
        student = pickle.load(file2)
        print(student[key])
        file2.close()
    else:
        print("Student not found!")
    ans = input("Do you want to search again? (y/n): ")
    while (ans.lower() != 'y') and (ans.lower() != 'n'):
        ans = input("Invalid input! Please enter 'y' or 'n': ")
        
while ans.lower() == 'n':
    print("Thank you for using our service!")
    break
