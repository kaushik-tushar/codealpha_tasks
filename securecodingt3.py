import sqlite3
import os
import subprocess


API_KEY = "123456789_SECRET"

def get_user_data(user_id):
    """Retrieves user data from the database using insecure SQL query"""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # 🚨 SQL Injection Vulnerability 🚨
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    data = cursor.fetchall()
    conn.close()
    
    return data

def execute_command(command):
    """Executes a system command (Command Injection Risk)"""
    # 🚨 Command Injection Vulnerability 🚨
    return subprocess.run(command, shell=True)

def save_to_file(filename, data):
    """Writes data to a file without proper validation"""
    # 🚨 Insecure File Handling 🚨
    with open(filename, "w") as f:
        f.write(data)

# Example Usage
user_data = get_user_data(1)
print(user_data)

execute_command("ls -la")

save_to_file("output.txt", "Sensitive Data")
