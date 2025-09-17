from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship, declarative_base, Session

SECRET_KEY = "CHANGE_THIS_SECRET"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DATABASE_URL = "sqlite:///./helpdesk.db"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI(title="HelpDesk API", version="1.0")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="client")  # admin, agent, client
    created_at = Column(DateTime, default=datetime.utcnow)

    tickets_created = relationship("Ticket", back_populates="creator", foreign_keys="Ticket.creator_id")
    tickets_assigned = relationship("Ticket", back_populates="agent", foreign_keys="Ticket.assigned_to_id")
    comments = relationship("Comment", back_populates="author")


class Category(Base):
    __tablename__ = "categories"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(Text, nullable=True)

    tickets = relationship("Ticket", back_populates="category")


class Status(Base):
    __tablename__ = "statuses"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)

    tickets = relationship("Ticket", back_populates="status")


class Priority(Base):
    __tablename__ = "priorities"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)

    tickets = relationship("Ticket", back_populates="priority")


class Ticket(Base):
    __tablename__ = "tickets"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    creator_id = Column(Integer, ForeignKey("users.id"))
    assigned_to_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    category_id = Column(Integer, ForeignKey("categories.id"), nullable=True)
    status_id = Column(Integer, ForeignKey("statuses.id"), nullable=True)
    priority_id = Column(Integer, ForeignKey("priorities.id"), nullable=True)

    creator = relationship("User", back_populates="tickets_created", foreign_keys=[creator_id])
    agent = relationship("User", back_populates="tickets_assigned", foreign_keys=[assigned_to_id])
    category = relationship("Category", back_populates="tickets")
    status = relationship("Status", back_populates="tickets")
    priority = relationship("Priority", back_populates="tickets")
    comments = relationship("Comment", back_populates="ticket")


class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True, index=True)
    ticket_id = Column(Integer, ForeignKey("tickets.id"), nullable=False)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    ticket = relationship("Ticket", back_populates="comments")
    author = relationship("User", back_populates="comments")

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str] = None


class UserCreate(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    role: Optional[str] = "client"


class UserOut(BaseModel):
    id: int
    full_name: str
    email: EmailStr
    role: str
    created_at: datetime

    class Config:
        orm_mode = True


class CategoryOut(BaseModel):
    id: int
    name: str
    description: Optional[str]

    class Config:
        orm_mode = True


class StatusOut(BaseModel):
    id: int
    name: str

    class Config:
        orm_mode = True


class PriorityOut(BaseModel):
    id: int
    name: str

    class Config:
        orm_mode = True


class CommentCreate(BaseModel):
    message: str


class CommentOut(BaseModel):
    id: int
    ticket_id: int
    author_id: int
    message: str
    created_at: datetime

    class Config:
        orm_mode = True


class TicketCreate(BaseModel):
    title: str
    description: Optional[str] = None
    category_id: Optional[int] = None
    priority_id: Optional[int] = None
    assigned_to_id: Optional[int] = None


class TicketOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    created_at: datetime
    updated_at: datetime
    creator_id: Optional[int]
    assigned_to_id: Optional[int]
    category: Optional[CategoryOut] = None
    status: Optional[StatusOut] = None
    priority: Optional[PriorityOut] = None
    comments: List[CommentOut] = []

    class Config:
        orm_mode = True

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = get_user_by_email(db, token_data.email)
    if user is None:
        raise credentials_exception
    return user


def get_current_active_user(current_user: User = Depends(get_current_user)):
    return current_user

@app.post("/signup", response_model=UserOut, status_code=201)
def signup(user_in: UserCreate, db: Session = Depends(get_db)):
    """
    Create a new user.
    Responses: 201 Created, 400 Bad Request
    """
    existing = get_user_by_email(db, user_in.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(
        full_name=user_in.full_name,
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        role=user_in.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Obtain JWT token.
    Responses: 200 OK, 401 Unauthorized
    """
    user = get_user_by_email(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users", response_model=List[UserOut])
def list_users(db: Session = Depends(get_db), current: User = Depends(get_current_active_user)):
    """
    List users. Requires authentication.
    Responses: 200 OK, 401 Unauthorized
    """
    users = db.query(User).all()
    return users


# ---------- Routes: Tickets ----------
@app.get("/tickets", response_model=List[TicketOut])
def get_tickets(db: Session = Depends(get_db), current: User = Depends(get_current_active_user)):
    """
    Get list of tickets.
    Responses: 200 OK, 401 Unauthorized
    """
    tickets = db.query(Ticket).all()
    return tickets


@app.post("/tickets", response_model=TicketOut, status_code=201)
def create_ticket(payload: TicketCreate, db: Session = Depends(get_db), current: User = Depends(get_current_active_user)):
    """
    Create a ticket.
    Responses: 201 Created, 400 Bad Request, 401 Unauthorized
    """
    ticket = Ticket(
        title=payload.title,
        description=payload.description,
        creator_id=current.id,
        assigned_to_id=payload.assigned_to_id,
        category_id=payload.category_id,
        priority_id=payload.priority_id,
        status_id=None
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)
    return ticket


@app.get("/tickets/{ticket_id}", response_model=TicketOut)
def get_ticket(ticket_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_active_user)):
    """
    Get ticket by id.
    Responses: 200 OK, 401 Unauthorized, 404 Not Found
    """
    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket


@app.put("/tickets/{ticket_id}", response_model=TicketOut)
def update_ticket(ticket_id: int, payload: TicketCreate, db: Session = Depends(get_db), current: User = Depends(get_current_active_user)):
    """
    Update a ticket (title/description/assignment/category/priority).
    Responses: 200 OK, 400 Bad Request, 401 Unauthorized, 404 Not Found
    """
    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    if not (current.role in ("admin", "agent") or ticket.creator_id == current.id):
        raise HTTPException(status_code=401, detail="Not authorized to update ticket")

    ticket.title = payload.title
    ticket.description = payload.description
    ticket.assigned_to_id = payload.assigned_to_id
    ticket.category_id = payload.category_id
    ticket.priority_id = payload.priority_id
    ticket.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(ticket)
    return ticket


@app.delete("/tickets/{ticket_id}", status_code=200)
def delete_ticket(ticket_id: int, db: Session = Depends(get_db), current: User = Depends(get_current_active_user)):
    """
    Delete a ticket.
    Responses: 200 OK, 401 Unauthorized, 404 Not Found
    """
    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    if not (current.role == "admin" or ticket.creator_id == current.id):
        raise HTTPException(status_code=401, detail="Not authorized to delete ticket")
    db.delete(ticket)
    db.commit()
    return {"detail": "Ticket deleted"}

@app.post("/tickets/{ticket_id}/comments", response_model=CommentOut, status_code=201)
def add_comment(ticket_id: int, payload: CommentCreate, db: Session = Depends(get_db), current: User = Depends(get_current_active_user)):
    """
    Add a comment to a ticket.
    Responses: 201 Created, 400 Bad Request, 401 Unauthorized, 404 Not Found
    """
    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    comment = Comment(ticket_id=ticket_id, author_id=current.id, message=payload.message)
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return comment

def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    if not db.query(Status).first():
        db.add_all([Status(name="Open"), Status(name="In Progress"), Status(name="Resolved")])
    if not db.query(Priority).first():
        db.add_all([Priority(name="Low"), Priority(name="Medium"), Priority(name="High")])
    if not db.query(Category).first():
        db.add_all([Category(name="General", description="General issues")])
    if not db.query(User).filter(User.email=="admin@example.com").first():
        admin = User(full_name="Admin", email="admin@example.com", hashed_password=get_password_hash("adminpass"), role="admin")
        db.add(admin)
    db.commit()
    db.close()

init_db()