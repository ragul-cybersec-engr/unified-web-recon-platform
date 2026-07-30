import bcrypt

password = "Hacker@123"
hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

print(hashed)