import sqlite3
import os
import subprocess


API_KEY = "123456789_SECRET"

def get_user_data(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    data = cursor.fetchall()
    conn.close()
    
    return data

def execute_command(command):

    return subprocess.run(command, shell=True)

def save_to_file(filename, data):
    with open(filename, "w") as f:
        f.write(data)

user_data = get_user_data(1)
print(user_data)

execute_command("ls -la")

save_to_file("output.txt", "Sensitive Data")
