from schemas.users.user_shema import AllUsersGet, UserCreate, SingleUserGet
from db.models import User
from db.db import session
from security.hash_token import get_token, decode_token
from security.hash_password import encrypt_password, check_password
from fastapi import Depends, FastAPI, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.exceptions import HTTPException


app = FastAPI(
title='Keystone'
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_user(username: str):
    user = session.query(User).filter(User.username.is_(username)).first()
    return SingleUserGet(email=user.email, username=user.username, password=user.password, user_id=user.user_id, is_active=user.is_active, is_admin=user.is_admin, is_superuser=user.is_superuser) if user else None


def create_user(user: UserCreate):
    password = encrypt_password(user.password)
    user_data = User(email=user.email, username=user.username, password=password,
                     is_active=user.is_active, is_admin=user.is_admin, is_superuser=user.is_superuser)
    return user_data


def validate_userdata(user: UserCreate):
    if session.query(User).filter(User.email.is_(user.email)).first():
        raise IOError('Email Already in use')
    if session.query(User).filter(User.username.is_(user.username)).first():
        raise IOError('Username Already in use')
    if len(user.password) < 8:
        raise IOError('Password cannot be less than 8 characters')


def get_current_user(token: str = Depends(oauth2_scheme)):
    print(token)
    try:
        username = decode_token(token)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = get_user(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    else:
        return user


@app.post('/users/')
def create_user_view(user: UserCreate):
    try:
        validate_userdata(user)
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))
    user_data = create_user(user)
    session.add(user_data)
    session.commit()
    return SingleUserGet(email=user_data.email, username=user_data.username, password=user_data.password, user_id=user_data.user_id, is_active=user_data.is_active, is_admin=user_data.is_admin, is_superuser=user_data.is_superuser)


@app.post('/users/admin/')
def create_admin_user_view(user: UserCreate):
    try:
        validate_userdata(user)
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))
    user.is_admin = True
    user.is_superuser = True
    user_data = create_user(user)
    session.add(user_data)
    session.commit()
    return SingleUserGet(email=user_data.email, username=user_data.username, password=user_data.password, user_id=user_data.user_id, is_active=user_data.is_active, is_admin=user_data.is_admin, is_superuser=user_data.is_superuser)


@app.get('/users/')
def get_all_users():
    users = [{'user_id': x.user_id, 'username': x.username, 'email': x.email,
              'password': x.password, 'is_active': x.is_active} for x in session.query(User)]
    if users:
        return {'users': users}
    else:
        raise HTTPException(status_code=404, detail="No Users in DB")


@app.get('/users/me')
def get_current_active_user(current_user: SingleUserGet = Depends(get_current_user)):
    return current_user


@app.get('/users/{user_id}')
def get_single_user(user_id: int):
    user = session.query(User).filter(User.user_id.is_(user_id)).first()
    if user:
        return SingleUserGet(user_id=user.user_id, username=user.username, email=user.email, password=user.password, is_active=user.is_active, is_suspended=user.is_suspended, is_admin=user.is_admin)
    else:
        raise HTTPException(status_code=404, detail="User not found")


@app.post('/token')
def get_token_view(form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username
    user = get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not check_password(user.password, form_data.password):
        raise HTTPException(status_code=404, detail="Invalid Password")
    else:
        token = get_token(username)
        return {"access_token": token, "token_type": "bearer"}
