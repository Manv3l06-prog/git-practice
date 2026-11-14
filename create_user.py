from app import User

user = User(username="James", age=20)

print(user.model_dump())

