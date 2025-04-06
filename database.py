import hashlib
import sqlite3

conn=sqlite3.connect('user.db',check_same_thread=False)
cursor=conn.cursor()
conn.execute('''
CREATE TABLE IF NOT EXISTS users (
    username varchar(50) PRIMARY KEY,
    password varchar(50) NOT NULL,
    "group" varchar(50) NOT NULL
)
''')

def register(username,password,group):
    try:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        cursor.execute("insert into users(username,password,'group') values(?,?,?)",(username,hashed_password,group))
        conn.commit()
        print("Registered successfully")
    except Exception as e:
        print("Registration failed "+str(e))
def login(username,password):
    try:
        db_password = cursor.execute("select password from users where username = ?",(username,)).fetchone()[0]
        if password ==db_password:
            return True
        return False
    except Exception as e:
        print("Login failed "+str(e))
def check_user(username):
    try:
        db_username = cursor.execute("select username from users where username = ?",(username,)).fetchone()[0]
        if db_username == username:
            return True
        return False
    except Exception as e:
        return False
conn.commit()
