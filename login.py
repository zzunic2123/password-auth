import sys
import getpass
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import bcrypt

DATA_FILE = "user.txt"
DELIMITER = ":::"

class user:
  def __init__(self, username, password, force_pass = False):
    self.username = username
    self.password = password
    self.force_pass = force_pass


def load_user_data():
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

def hash(data, salt):
    return bcrypt.hashpw(data.encode('utf-8'), salt)

def generate_salt():
    return bcrypt.gensalt()

def login(username):
    data = load_user_data()
    username_encoded=username.encode('utf-8')

    hashed = None
    for x in data.keys():
        if bcrypt.checkpw(username_encoded,x.encode()):
            hashed = x

    if not hashed:
        print(f"User '{username}' does not exist.")
        return
    for _ in range(3):
        password = getpass.getpass("Password: ")
        if bcrypt.checkpw(password.encode(), data[hashed]['password'].encode()):
            if data[hashed]['force_change'].strip() == 'True':
                new_password = getpass.getpass("New password: ")
                # if(new_password == password):
                #     print('New password is same as old password')
                #     sys.exit()
                confirm_password = getpass.getpass("Repeat new password: ")
                if new_password == confirm_password:
                    new_user = user(hashed, hash(new_password,generate_salt()), False)
                    replace_user_data(new_user)
                    print("Login successful.")
                    sys.exit()
                else:
                    print("New passwords do not match. Login failed.")
                    sys.exit()
            else:
                print("Login successful.")
                sys.exit()
        else:
            print("Username or password incorrect.")
    else:
        print("3 failed login attempts. Exiting.")

def main():
    if len(sys.argv) < 2:
        print("Usage: login.py <username>")
        return

    username = sys.argv[1]
    if login(username):
        print("Login successful.")
    else:
        print("Username or password incorrect.")

if __name__ == "__main__":
    main()
    


