from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from typing import List, Optional
import os

# Security imports
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta

# SQLAlchemy imports
from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.orm import sessionmaker, Session, declarative_base

app = FastAPI()

# ==========================================
# 1. SECURITY CONFIGURATION (The Bouncer's Rulebook)
# ==========================================
SECRET_KEY = os.environ.get("SECRET_KEY", "super-secret-key-that-you-should-never-commit-to-github")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ==========================================
# 2. DATABASE SETUP (The Warehouse)
# ==========================================
# If Render provides a DATABASE_URL, use it. Otherwise, use local SQLite.
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./brewmaster.db")

if DATABASE_URL.startswith("postgres"):
    # For Render/Postgres
    engine = create_engine(DATABASE_URL)
else:
    # For Local/SQLite
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ==========================================
# 3. DATABASE MODELS (The Warehouse Shelves)
# ==========================================
class CoffeeDB(Base):
    __tablename__ = "coffees"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String, index=True)
    description = Column(String, nullable=True)
    price = Column(Float)

class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="customer")

# Create tables in the database
Base.metadata.create_all(bind=engine)

# ==========================================
# 4. PYDANTIC SCHEMAS (The Order Forms)
# ==========================================
class CoffeeCreate(BaseModel):
    name: str
    description: Optional[str] = None
    price: float = Field(gt=0)

class CoffeeResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    price: float
    
    class Config:
        from_attributes = True

class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "customer"

class UserResponse(BaseModel):
    id: int
    username: str
    role: str
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

# ==========================================
# 5. HELPER FUNCTIONS (The Blenders & Wristband Makers)
# ==========================================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ==========================================
# 6. DEPENDENCIES (The VIP Bouncers)
# ==========================================
def get_current_user(
    db: Session = Depends(get_db), 
    token: str = Depends(oauth2_scheme)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    user = db.query(UserDB).filter(UserDB.username == username).first()
    if user is None:
        raise credentials_exception
    return user

def get_manager_user(current_user: UserDB = Depends(get_current_user)):
    if current_user.role != "manager":
        raise HTTPException(status_code=403, detail="Access denied. Managers only!")
    return current_user

# ==========================================
# 7. THE ROUTES (The Waiters)
# ==========================================

# --- USER REGISTRATION ---
@app.post("/users/register", response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(UserDB).filter(UserDB.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_pw = get_password_hash(user.password)
    db_user = UserDB(username=user.username, hashed_password=hashed_pw, role=user.role)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# --- LOGIN (Get your Wristband) ---
@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    return {"access_token": access_token, "token_type": "bearer"}

# --- COFFEE ROUTES ---
@app.post("/coffees/", response_model=CoffeeResponse)
def create_coffee(coffee: CoffeeCreate, db: Session = Depends(get_db), manager: UserDB = Depends(get_manager_user)):
    db_coffee = CoffeeDB(name=coffee.name, description=coffee.description, price=coffee.price)
    db.add(db_coffee)
    db.commit()
    db.refresh(db_coffee)
    return db_coffee

@app.get("/coffees/", response_model=List[CoffeeResponse])
def read_coffees(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(CoffeeDB).offset(skip).limit(limit).all()

@app.put("/coffees/{coffee_id}", response_model=CoffeeResponse)
def update_coffee(coffee_id: int, coffee: CoffeeCreate, db: Session = Depends(get_db), manager: UserDB = Depends(get_manager_user)):
    db_coffee = db.query(CoffeeDB).filter(CoffeeDB.id == coffee_id).first()
    if not db_coffee:
        raise HTTPException(status_code=404, detail="Coffee not found")
    db_coffee.name = coffee.name
    db_coffee.description = coffee.description
    db_coffee.price = coffee.price
    db.commit()
    db.refresh(db_coffee)
    return db_coffee

@app.delete("/coffees/{coffee_id}")
def delete_coffee(coffee_id: int, db: Session = Depends(get_db), manager: UserDB = Depends(get_manager_user)):
    db_coffee = db.query(CoffeeDB).filter(CoffeeDB.id == coffee_id).first()
    if not db_coffee:
        raise HTTPException(status_code=404, detail="Coffee not found")
    db.delete(db_coffee)
    db.commit()
    return {"message": "Coffee deleted"}

# ==========================================
# 8. BACKGROUND TASKS (The Dishwasher)
# ==========================================
def send_restock_email(coffee_name: str, quantity: int, supplier_email: str):
    import time
    print(f"\n[BACKGROUND TASK STARTED] Preparing to email {supplier_email} about {quantity} units of {coffee_name}...")
    time.sleep(3) 
    print(f"[BACKGROUND TASK COMPLETE] ✅ Successfully emailed {supplier_email}!\n")

@app.post("/coffees/{coffee_id}/restock")
def restock_coffee(
    coffee_id: int, 
    quantity: int, 
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db), 
    manager: UserDB = Depends(get_manager_user)
):
    db_coffee = db.query(CoffeeDB).filter(CoffeeDB.id == coffee_id).first()
    if not db_coffee:
        raise HTTPException(status_code=404, detail="Coffee not found")
    
    background_tasks.add_task(send_restock_email, db_coffee.name, quantity, "supplier@coffeebeans.com")
    
    return {
        "message": f"Restock order for {quantity} units of {db_coffee.name} initiated.",
        "status": "Supplier will be notified in the background."
    }