from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException
from pwdlib import PasswordHash


app = FastAPI()
password_hash = PasswordHash.recommended()

users = {}
next_user_id = 1

class User(BaseModel):
    username: str
    age: int = Field(ge=0)
    password: str = Field(min_length=8)
    is_active: bool = True

class UserPublic(BaseModel):
    id: int
    username: str
    age: int
    is_active: bool
    role: str

@app.post("/users", response_model=UserPublic)
async def create_user(user: User):
    global next_user_id

    user_id = next_user_id

    users[user_id] = {
        **user.model_dump(exclude={"password"}),
        "password": password_hash.hash(user.password),
        "role": "user"
    }

    next_user_id += 1
    return {"id": user_id, **users[user_id]}

@app.get("/users/{user_id}", response_model=UserPublic)
async def get_user(user_id: int):
    if user_id not in users:
        raise HTTPException(
            status_code=404,
            detail="Пользователь не найден",
        )

    return {"id": user_id, **users[user_id]}