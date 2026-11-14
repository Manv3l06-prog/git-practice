from pydantic import BaseModel, Field, EmailStr
from fastapi import FastAPI, HTTPException, Depends
from pwdlib import PasswordHash
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import os
import secrets

reset_tokens = {}


from pygments.lexers import data

app = FastAPI()
password_hash = PasswordHash.recommended()
security = HTTPBasic()
products = {}
next_product_id = 1

admin_password = os.getenv("ADMIN_PASSWORD")

if not admin_password:
    admin_password = "admin12345"

users = {
    1: {
        "username": "admin",
        "email": "admin@example.com",
        "age": 20,
        "is_active": True,
        "role": "admin",
    }
}

next_user_id = 2

class User(BaseModel):
    username: str
    email: EmailStr
    age: int = Field(ge=0)
    password: str = Field(min_length=8)
    is_active: bool = True

class UserPublic(BaseModel):
    id: int
    username: str
    email: EmailStr
    age: int
    is_active: bool
    role: str

class Product(BaseModel):
    name: str = Field(min_length=1)
    price: int = Field(gt=0)
    quantity: int = Field(ge=0)

class EmailChange(BaseModel):
    new_email: EmailStr

class PasswordChange(BaseModel):
    old_password: str
    new_password: str = Field(min_length=8)

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(min_length=8)

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

@app.patch("/me/email", response_model=UserPublic)
def change_email(
    data: EmailChange,
    current_user: dict = Depends(get_current_user),
):
    for user_id, stored_user in users.items():
        if (
            stored_user.get("email") == data.new_email
            and user_id != current_user["id"]
        ):
            raise HTTPException(
                status_code=409,
                detail="Этот email уже используется",
            )

    user_id = current_user["id"]

    users[user_id]["email"] = data.new_email

    return {
        "id": user_id,
        **users[user_id],
    }

@app.patch("/me/password")
def change_password(
        data: PasswordChange,
        current_user: dict = Depends(get_current_user),
):
    user_id = current_user["id"]

    old_password_is_correct = password_hash.verify(
        data.old_password,
        users[user_id]["password_hash"]
    )

    if not old_password_is_correct:
        raise HTTPException(
            status_code=400,
            detail = "Старый пароль неверный"
        )

    users[user_id]["password_hash"] = password_hash.hash(
        data.new_password,
    )

    return{
        "message": "Пароль успешно изменен"
    }

@app.post("/password-reset/request")
def request_password_reset(
        data: PasswordResetRequest
):

    for user_id, stored_user in users.items():
        if stored_user.get("email") == data.email:

            token = secrets.token_urlsafe(32)

            reset_tokens[token] = user_id

            return{
                "message": "Зарос на сброс пароля создан",
                "token": token,
            }

        raise HTTPException(
            status_code = 404,
            detail = "Пользователь стаким email не найден",
        )

@app.post("/password-reset/confirm")
def confirm_password_reset(
        data: PasswordResetConfirm,
):
    if data.token not in reset_tokens:
        raise HTTPException(
            status_code = 400,
            detail = "Неверный или недействительный пароль"
        )

    user_id = reset_tokens[data.token]

    users[user_id]["password_hash"] = password_hash.hash(
        data.new_password,
    )

    del reset_tokens[data.token]

    return{
        "message": "Пароль успешно изменен"
    }