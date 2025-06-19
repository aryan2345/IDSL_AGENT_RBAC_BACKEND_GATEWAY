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
from fastapi.openapi.utils import get_openapi  # 🆕 for Swagger Bearer support

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# FastAPI app setup
app = FastAPI()

# Include route modules
app.include_router(login_router)
app.include_router(data_router)
app.include_router(chat_router)

@app.on_event("startup")
def startup():
    # MongoDB setup
    client = MongoClient(os.getenv("MONGO_URL"))
    db = client.get_database(name='mydb')
    collection_name = "chats"

    if collection_name not in db.list_collection_names():
        db.create_collection(collection_name, check_exists=True)

    logging.info(f"Connected to MongoDB database '{db.name}' and collection '{collection_name}'.")

    # PostgreSQL setup
    db = PostgresSQL()
    with open('./database/create_tables.sql', 'r') as sql:
        db.execute_query(sql.read())
    result = db.fetch_one("SELECT COUNT(*) FROM users")

    if result["count"] == 0:
        user_id = str(uuid.uuid4())
        hashed_password = hash_password("admin")
        db.execute_query(
            "INSERT INTO users (user_id, username, password_hash, role) VALUES (%s, %s, %s, %s)",
            (user_id, "admin", hashed_password, "system_admin")
        )
        logging.info("No users found in the system. Admin user created!")

@app.get("/health")
def health():
    return {"status": "Service is running!"}

# 🆕 Swagger UI Bearer token support
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="My API",
        version="1.0.0",
        description="API with JWT Bearer authentication",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "HTTPBearer": {
            "type": "http",
            "scheme": "bearer"
        }
    }
    for path in openapi_schema["paths"]:
        for method in openapi_schema["paths"][path]:
            if method in ["get", "post", "put", "delete"]:
                openapi_schema["paths"][path][method]["security"] = [{"HTTPBearer": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi
