from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import jwt  

import models
from database import engine, SessionLocal
from schemas import UserCreate, UserLogin

# Create tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "mysecret"

# DB connection
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def home():
    return {"message": "Hello Pavan!"}

# SIGNUP
@app.post("/signup")
def signup(user: UserCreate, db: Session = Depends(get_db)):
    hashed_password = pwd_context.hash(user.password)

    new_user = models.User(
        username=user.username,
        password=hashed_password
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User created successfully"}

# LOGIN
@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()

    if not db_user:
        return {"message": "User not found"}

    if not pwd_context.verify(user.password, db_user.password):
        return {"message": "Wrong password"}

    token = jwt.encode({"username": user.username}, SECRET_KEY, algorithm="HS256")

    return {"token": token}

# PROFILE
@app.get("/profile")
def profile(token: str):
    data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    return {"user": data}