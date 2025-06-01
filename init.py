from app import register_admin
from getpass import getpass

username = input("Please enter the username of the administrator: ")
password = getpass("Please enter the password of the administrator: ")
register_admin(username, password)
