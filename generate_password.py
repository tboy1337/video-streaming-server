from werkzeug.security import generate_password_hash

password = input("Enter your password: ")
password_hash = generate_password_hash(password)
print("Password Hash")
print(password_hash)
