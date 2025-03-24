#Create a Binary file for students with name, roll no, and marks, search the roll number of a studnet and updats his/her marks
import pickle, os
os.system('cls')
file1 = open('student_records.dat', 'wb')
studentslist = []
rollnos = []
found = False
ans = 'y'
while ans.lower() == 'y':
    os.system('cls')
    print('Enter Student Details')
    students = {}
    rollno = int(input('Enter Roll No: '))
    name = input('Enter Name: ')
    marks = float(input('Enter Marks: '))
    students["Roll No"] = rollno
    students["Name"] = name
    students["Marks"] = marks
    studentslist.append(students)
    rollnos.append(rollno)
    olddata = studentslist
    ans = input('Do you want to add more records? (y/n): ')
    while ans.lower() != 'y' and ans.lower() != 'n':
        ans = input('Invalid choice! Enter y/n: ')
while ans.lower() == 'n':
    print(len(studentslist), 'records added successfully!')
    break
pickle.dump(studentslist, file1)
file1.close()
input('Press Enter to Continue')
ans2 = 'y'
file2 = open('student_newrecords.dat', 'wb')
while ans2.lower() == 'y':
    os.system('cls')
    print('Student record Correction')
    searchrollno = int(input('Enter Roll No to search: '))
    for student in studentslist:
        if student['Roll No'] == searchrollno:
            print(student)
            newmarks = float(input('Enter New marks'))
            found = True
            student['Marks'] = newmarks
    if found == False:
        print('Student not found')
    pickle.dump(studentslist, file2)
    ans2 = input('Do you Want to Continue Modifications?(y/n):')
    while ans2.lower() != 'y' and ans2.lower() != 'n':
        ans2 = input('Invalid choice! Enter y/n: ')
while ans2.lower() == 'n':
    print('Goodbye!')
    break
file2.close()
os.system('cls')
print('Student Records Updated Successfully!')
file3 = open('student_records.dat', 'rb')
file4 = open('student_newrecords.dat', 'rb')
try:
    while True:
        olddisp = pickle.load(file3)
        newdisp = pickle.load(file4)
        totaldata = len(olddisp)
        for datano in range(totaldata):
            print('Old Data:', olddisp[datano])
            print('New Data:', newdisp[datano])
except EOFError:
    file3.close()
    file4.close()
        