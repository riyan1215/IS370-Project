import hashlib

from utility import database
name=True
#really complicated to implement registering into a server.py without an api connecting to the db
while name:
    print("---------------------------------------")
    print("1. Register")
    print("2. Groups")
    print("3. Exit")
    print("---------------------------------------")
    input1 = int(input("Enter your choice : "))
    if input1 == 1:
        print("---------------------------------------")
        input_username=input("Enter username: ")
        input_password=input("Enter password: ")
        hashlib.sha256(input_password.encode()).hexdigest()
        status= database.register(input_username, hashlib.sha256(input_password.encode()).hexdigest())
        if status:
            print("Registration successful")
            continue
        else:
            print("Registration failed")
            continue
    if input1 == 2:
        print("---------------------------------------")
        input_username = input("Enter username: ")
        status = database.check_user(input_username)
        if status:
            print("Username exists")
            print("---------------------------------------")
            print("1. Add to group")
            print("2. Back to main menu:")
            print("3. Exit")
            input2 = int(input("Enter your choice: "))
            if input2 == 1:
                print("---------------------------------------")
                groups= database.group_list()
                print("Groups:")
                print(groups)
                print("----------------------------------------")
                print("Or create a new group with a new name")
                input_group_name = input("Enter group name: ")
                status= database.add_user_to_group(input_username, input_group_name)
                if status:
                    print("User added to group")
                else:
                    print("User not added to group")
                continue
            if input2 == 2:
                continue
            if input2 == 3:
                name=False
    if input1 == 3:
        name=False
