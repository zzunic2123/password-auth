import sys
import getpass
import bcrypt
import os



DATA_FILE = "user.txt"
DELIMITER = ":::"

class user:
  def __init__(self, username, password, force_pass = False):
    self.username = username
    self.password = password
    self.force_pass = force_pass


def load_user_data():

    if not os.path.isfile(DATA_FILE):
        f = open(DATA_FILE, "w")
        f.close()

    f = open(DATA_FILE, "r+")
    dict_of_users = {}
    while True:
        line = f.readline()
        if not line:
            break

        list = line.split(DELIMITER)
        new_user = user(list[0],list[1],list[2])

        dict_of_users[new_user.username] = {
            "password": new_user.password,
            "force_change": new_user.force_pass
        }

    f.close()
    return dict_of_users

def save_user_data(new_user):
    if not os.path.isfile(DATA_FILE):
        f = open(DATA_FILE, "w")
        f.close()
    f = open(DATA_FILE, "a")
    line = new_user.username.decode() + DELIMITER + new_user.password.decode() + DELIMITER + str(new_user.force_pass) + '\n'
    f.write(line)
    f.close()

def replace_user_data(new_user):
    lines = open(DATA_FILE, 'r').readlines()
    cnt = 0
    for i,x in enumerate(lines):
        if new_user.username in x:
            cnt = i
            break
    supst = new_user.username + DELIMITER + new_user.password.decode() + DELIMITER + str(new_user.force_pass) + '\n'
    lines[cnt] = supst

    out = open(DATA_FILE, 'w')
    out.writelines(lines)
    out.close()

def remove_user_from_file(hashed):
    lines = open(DATA_FILE, 'r').readlines()
    cnt = 0
    for i,x in enumerate(lines):
        if hashed in x:
            cnt = i
            break

    supst = ''
    lines[cnt] = supst
    out = open(DATA_FILE, 'w')
    out.writelines(lines)
    out.close()

def hash(data, salt):
    return bcrypt.hashpw(data.encode('utf-8'), salt)

def generate_salt():
    return bcrypt.gensalt()

def add_user(username):
    data = load_user_data()

    for x in data.keys():
        if bcrypt.checkpw(username.encode(),x.encode()):
            print(f"User '{username}' already exists.")
            return
    
    
    password = getpass.getpass("Password: ")
    password_confirmation = getpass.getpass("Repeat Password: ")

    if password != password_confirmation:
        print("User add failed. Password mismatch.")
        return

    hashed_password = hash(password, generate_salt())
    hashed_username = hash(username, generate_salt())

    new_user = user(hashed_username, hashed_password, False)

    save_user_data(new_user)
    print(f"User '{username}' successfully added.")


def change_password(username):
    data = load_user_data()

    hashed = None
    for x in data.keys():
        if bcrypt.checkpw(username.encode(),x.encode()):
            hashed = x

    if not hashed:
        print(f"User '{username}' does not exist.")
        return
    
    curr_user = user(hashed, data[hashed]['password'], data[hashed]['force_change'])

    password = getpass.getpass("Password: ")
    password_confirmation = getpass.getpass("Repeat Password: ")

    if password != password_confirmation:
        print("Password change failed. Password mismatch.")
        return
    
    curr_user.password = hash(password,generate_salt())
    curr_user.force_pass = False

    replace_user_data(curr_user)
    print("Password change successful.")

def replace_user_data_forcepass(new_user):
    lines = open(DATA_FILE, 'r').readlines()
    cnt = 0
    for i,x in enumerate(lines):
        if new_user.username in x:
            cnt = i
            break
    supst = new_user.username + DELIMITER + new_user.password + DELIMITER + str(new_user.force_pass) + '\n'
    lines[cnt] = supst

    out = open(DATA_FILE, 'w')
    out.writelines(lines)
    out.close()



def force_password_change(username):
    data = load_user_data()

    hashed = None
    for x in data.keys():
        if bcrypt.checkpw(username.encode(),x.encode()):
            hashed = x

    if not hashed:
        print(f"User '{username}' does not exist.")
        return


    new_user = user(hashed, data[hashed]['password'], True)
    replace_user_data_forcepass(new_user)
    print(f"User '{username}' will be requested to change password on next login.")


def remove_user(username):
    data = load_user_data()

    hashed = None
    for x in data.keys():
        if bcrypt.checkpw(username.encode(),x.encode()):
            hashed = x

    if not hashed:
        print(f"User '{username}' does not exist.")
        return

    remove_user_from_file(hashed)
    print(f"User '{username}' successfully removed.")

def main():
    if len(sys.argv) < 3:
        print("Usage: usermgmt.py <command> <username>")
        return

    command = sys.argv[1]
    username = sys.argv[2]

    if command == "add":
        add_user(username)
    elif command == "passwd":
        change_password(username)
    elif command == "forcepass":
        force_password_change(username)
    elif command == "del":
        remove_user(username)
    else:
        print("Invalid command.")

if __name__ == "__main__":
    main()
