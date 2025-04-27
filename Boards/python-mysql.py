import os
os.system('cls')
import mysql.connector as msc
mdb = msc.connect(host='localhost', 
                  user='root', 
                  password='VSrivastava@123', 
                  database='boards')
cursor = mdb.cursor()
file1 = open('C:\\Personal\\Varun\\Board\\Computer_Science\\Programs\\Scripts\\Boards\\test.txt', 'r')
queries = file1.readlines()
for query in queries:
    print(query)
    query = query.strip()  # Remove leading/trailing spaces and newlines
    if query:  # Skip empty lines
        print(query)
        cursor.execute(query)
        #queryrun = cursor.fetchall()
        #for output in queryrun:
        #    print(output)
        
mdb.commit()
cursor.close()
mdb.close()
file1.close()