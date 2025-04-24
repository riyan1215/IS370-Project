import hashlib
import sqlite3

conn = sqlite3.connect('../user.db', check_same_thread=False)
cursor = conn.cursor()
conn.execute('''
             CREATE TABLE IF NOT EXISTS users
             (
                 username TEXT PRIMARY KEY,
                 password TEXT NOT NULL
             )
             ''')
conn.execute('''
             CREATE TABLE IF NOT EXISTS users_group
             (
                 username   TEXT,
                 group_name TEXT,
                 FOREIGN KEY (username) REFERENCES users (username)
             )
             ''')


def add_user_to_group(username, group_name):
    try:
        user_groups = groups(username)
        if user_groups is None:
            user_groups = []
        if group_name not in user_groups and check_user(username):
            conn.execute('INSERT INTO users_group (username, group_name) VALUES (?, ?)', (username, group_name))
            conn.commit()
            print(f"{username} added to {group_name}")
            return True
        elif group_name in user_groups:
            print(f"{username} is already a member of {group_name}")
            return False
        else:
            print(f"{username} is not Registered")
            return False
    except Exception as e:
        print(f"Error adding user to group: {e}")
        return False


def register(username, password):
    try:
        cursor.execute('insert into users(username,password) values(?,?)', (username, password))
        conn.commit()
        return True
    except Exception as e:
        print("Registration failed " + str(e))
        return False


def login(username, password):
    try:
        db_password = cursor.execute('select password from users where username = ?', (username,)).fetchone()[0]
        if password == db_password:
            return True
        return False
    except Exception as e:
        print("Login failed " + str(e))


def check_user(username):
    try:
        db_username = cursor.execute('select username from users where username = ?', (username,)).fetchone()[0]
        if db_username == username:
            return True
        return False
    except Exception as e:
        return False


def groups(username):
    db_groups = cursor.execute('SELECT group_name FROM users_group WHERE username = ?', (username,)).fetchall()
    return [group[0] for group in db_groups] if db_groups else []


def group_members(group_name):
    db_members = cursor.execute('SELECT username FROM users_group WHERE group_name = ?', (group_name,)).fetchall()
    members = [member[0] for member in db_members]
    print(members)
    return members
def group_list():
    db_members = cursor.execute('SELECT Distinct group_name FROM users_group', ()).fetchall()
    if db_members:
        members = [member[0] for member in db_members]
        return members
    return []



conn.commit()
