from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, Depends
from pwdlib import PasswordHash
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import os



app = FastAPI()
password_hash = PasswordHash.recommended()
security = HTTPBasic()
products = {}
next_product_id = 1

users = {
    1: {
        "username": "admin",
        "age": 20,
        "is_active": True,
        "role": "admin",
        "password_hash": password_hash.hash(
            os.environ["ADMIN_PASSWORD"]
        ),
    }
}

next_user_id = 2

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

class Product(BaseModel):
    name: str = Field(min_length=1)
    price: int = Field(gt=0)
    quantity: int = Field(ge=0)

@app.post("/users", response_model=UserPublic)
async def create_user(user: User):
    global next_user_id
    for existing_user in users.values():
        if existing_user["username"] == user.username:
            raise HTTPException(
                status_code=409,
                detail = "Такой никнаейм уже занят"
            )

    user_id = next_user_id

    users[user_id] = {
        **user.model_dump(exclude={"password"}),
        "password_hash": password_hash.hash(user.password),
        "role": "user"
    }

    next_user_id += 1
    return {"id": user_id, **users[user_id]}


def get_current_user(
        credentials: HTTPBasicCredentials = Depends(security),
):
    for user_id, stored_user in users.items():
        if stored_user["username"] == credentials.username:
            password_is_correct = password_hash.verify(
                credentials.password,
                stored_user["password_hash"]
            )

            if not password_is_correct:
                break

            if not stored_user["is_active"]:
                raise HTTPException(
                    status_code=403,
                    detail="Пользователь отключен"
                )

            return {"id": user_id, **stored_user}

    raise HTTPException(
        status_code=401,
        detail="Неверное имя или пароль",
        headers={"WWW-Authenticate": "Basic"},
    )

@app.get("/me", response_model=UserPublic)
def get_my_profile(current_user: dict = Depends(get_current_user)):
    return current_user

def require_admin(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=403,
            detail="Недостаточно прав",
        )

    return current_user


@app.get("/users", response_model=list[UserPublic])
def get_all_users(admin: dict = Depends(require_admin)):
    return [
        {"id": user_id, **user_data}
        for user_id, user_data in users.items()
    ]

@app.get("/users/{user_id}", response_model=UserPublic)
def get_user(
    user_id: int,
    current_user: dict = Depends(get_current_user),
):
    is_admin = current_user["role"] == "admin"
    is_owner = current_user["id"] == user_id

    if not is_admin and not is_owner:
        raise HTTPException(
            status_code=403,
            detail="Нельзя просматривать чужой профиль",
        )

    if user_id not in users:
        raise HTTPException(
            status_code=404,
            detail="Пользователь не найден",
        )

    return {"id": user_id, **users[user_id]}

@app.post("/products", status_code=201)
def create_product(
    product: Product,
    admin: dict = Depends(require_admin),
):
    global next_product_id

    product_id = next_product_id
    products[product_id] = product.model_dump()
    next_product_id += 1

    return {"id": product_id, **products[product_id]}

@app.get("/products")
def get_all_products():
    return[
        {"id": product_id, **product_data}
        for product_id, product_data in products.items()
    ]