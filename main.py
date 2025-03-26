import logging
import os
import uuid
from fastapi import FastAPI
from pymongo import MongoClient
from routes.login import login_router
from routes.data import data_router
from routes.chat import chat_router
from database.postgres import PostgresSQL
from utils.helper import hash_password

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
app = FastAPI()
app.include_router(login_router)
app.include_router(data_router)
app.include_router(chat_router)


@app.on_event("startup")
def startup():
    # Set up the mongo db and collection
    client = MongoClient(os.getenv("MONGO_URL"))
    db = client.get_database(name='mydb')

    collection_name = "chats"
    db.create_collection(collection_name)
    logging.info(f"Connected to MongoDB database '{db.name}' and collection '{collection_name}'.")

    # Set up the Postgres connection
    db = PostgresSQL()
    # Check if there are any entries in the users table
    result = db.fetch_one("SELECT COUNT(*) FROM users")

    if result["count"] == 0:  # If no users exist, insert the admin user
        user_id = str(uuid.uuid4())  # Generate a unique user ID
        hashed_password = hash_password("admin")  # Hash the password 'admin'

        db.execute_query(
            "INSERT INTO users (user_id, username, password_hash, role) VALUES (%s, %s, %s, %s)",
            (user_id, "admin", hashed_password, "system_admin")
        )
        logging.info("No users found in the system. Admin user created!")

@app.get("/health")
def health():
    return {"status": "Service is running!"}