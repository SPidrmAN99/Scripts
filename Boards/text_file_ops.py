#Read a text file and write all the lines containing letter 'a' to another file
file1 = open("file1.txt", "w")
file1.write("Hello, World!\n")
file1.write("My name is Varun\n")
file1.write("I am a software developer\n")
file1.write("Nice to meet you!\n")
file1.close()
file2 = open("file1.txt", "r")
file3 = open("file2.txt", "w")
readlines = file2.readlines()
for line in readlines:
    if "a" in line:
        file3.write(line)
file2.close()
file3.close()
file4 = open("file2.txt", "r")
print(file4.readlines())
file4.close()
