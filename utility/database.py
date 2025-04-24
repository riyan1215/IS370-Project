import os
import sqlite3


def init_database(db_path='user.db'):
    # Make sure the directory exists
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

    # Create global connection and cursor
    global conn, cursor
    conn = sqlite3.connect(db_path, check_same_thread=False)
    cursor = conn.cursor()

    # Initialize tables
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
    conn.commit()


def add_user_to_group(username, group_name):
    try:
        user_groups = groups(username)
        if user_groups is None:
            user_groups = []
        if group_name not in user_groups and check_user(username):
            conn.execute('INSERT INTO users_group (username, group_name) VALUES (?, ?)', (username, group_name))
            conn.commit()
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
    return members
def group_list():
    db_members = cursor.execute('SELECT Distinct group_name FROM users_group', ()).fetchall()
    if db_members:
        members = [member[0] for member in db_members]
        return members
    return []



init_database()