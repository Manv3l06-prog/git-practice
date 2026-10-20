from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException


app = FastAPI()

users = {}
next_user_id = 1

class User(BaseModel):
    username: str
    age: int = Field(ge=0)
    is_active: bool = True

@app.post("/users")
async def create_user(user: User):
    global next_user_id

    user_id = next_user_id
    users[user_id] = user.model_dump()
    next_user_id += 1

    print("Содержимое хранилища:", users)
    return {"id": user_id, **users[user_id]}
@app.get("/users/{user_id}")
async def get_user(user_id: int):
    if user_id not in users:
        raise HTTPException(
            status_code=404,
            detail="Пользователь не найден",
        )

    return {"id": user_id, **users[user_id]}