from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
import enum

# Конфигурация
DATABASE_URL = "sqlite:///./test.db"
SECRET_KEY = "your_secret_key"  # Замените на ваш секретный ключ
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Настройка базы данных
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Модель ролей
class RoleEnum(str, enum.Enum):
    user = "user"
    admin = "admin"
    client = "client"
    doctor = "doctor"


# Модель пользователя
class UserDB(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    surname = Column(String, unique=True,index=True)
    email = Column(String, unique=True,index=True)
    age = Column(Integer, index=True)
    hashed_password = Column(String)
    role = Column(Enum(RoleEnum), default=RoleEnum.user)

class DoctorDB(Base):
    __tablename__ = "doctors"

    id = Column(Integer, primary_key=True, index=True)
    doctor_name = Column(String, unique=True, index=True)
    surname = Column(String, unique=True,index=True)
    specialization = Column(String, unique=True,index=True)
    category = Column(Integer, index=True)

class Observation_roomDB(Base):
    __tablename__ = "observation_rooms"

    id = Column(Integer, primary_key=True, index=True)
    number = Column(Integer, index=True)

class AppointmentDB(Base):
    __tablename__ = "appointments"

    id = Column(Integer, primary_key=True, index=True)
    date = Column(Integer, index=True)
    #doctor_id: Column(Integer, index=True)
    #client_id: Column(default=None, foreign_key="client.id")
    #observation_room_id: Optional[int] = Field(default=None, foreign_key="observation_room.id")

# Создание таблиц
Base.metadata.create_all(bind=engine)

# Настройка хэширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Настройка приложения
app = FastAPI()


# Модель для регистрации и входа
class User(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class UserInDB(User):
    hashed_password: str
    role: RoleEnum


# Зависимость для получения сессии базы данных
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Хешируем пароль
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


# Проверяем пароль
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# Генерация JWT токена
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(db, name: str):
    if name in db:
        user_dict = db[name]
        return UserInDB(**user_dict)


# Регистрация пользователя
@app.post("/auth/signup")
async def signup(user: User, db: Session = Depends(get_db)):
    if db.query(UserDB).filter(UserDB.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = hash_password(user.password)
    new_user = UserDB(username=user.username, hashed_password=hashed_password)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User registered successfully"}


# Вход в систему
@app.post("/auth/login", response_model=Token)
async def login(user: User, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.username == user.username).first()

    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username, "role": db_user.role.value},
                                       expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users", response_model=list[UserInDB])
async def get_users(db: Session = Depends(get_db)):
    users = db.query(UserDB).all()
    return [
        UserInDB(username=user.username, hashed_password=user.hashed_password, role=user.role)
        for user in users
    ]


@app.patch("/users/{username}", response_model=UserInDB)
async def update_user(username: str, user: User, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.username == username).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db_user.username = user.username
    db_user.hashed_password = create_password_hash(user.password)

    db.commit()
    db.refresh(db_user)

    return UserInDB(username=db_user.username, hashed_password=db_user.hashed_password, role=db_user.role)

@app.get("/users", response_model=list[UserInDB])
async def get_users(db: Session = Depends(get_db)):
    users = db.query(UserDB).all()
    return [
        UserInDB(username=user.username, hashed_password=user.hashed_password, role=user.role)
        for user in users
    ]

@app.delete("/users/{username}", response_model=dict)
async def delete_user(username: str, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.username == username).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(db_user)
    db.commit()

    return {"detail": "User deleted successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)