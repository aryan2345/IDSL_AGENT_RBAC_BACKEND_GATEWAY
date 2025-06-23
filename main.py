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
from fastapi.openapi.utils import get_openapi

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
    db_mongo = client.get_database(name='mydb')
    collection_name = "chats"

    if collection_name not in db_mongo.list_collection_names():
        db_mongo.create_collection(collection_name, check_exists=True)

    logging.info(f"Connected to MongoDB database '{db_mongo.name}' and collection '{collection_name}'.")

    # PostgreSQL setup
    db = PostgresSQL()

    # Run create_tables.sql statements one by one
    with open('./database/create_tables.sql', 'r') as sql_file:
        sql_script = sql_file.read()
        for statement in sql_script.split(';'):
            stmt = statement.strip()
            if stmt:
                db.execute_query(stmt + ';')

    # Insert hardcoded projects with UUIDs if they don't exist
    project_names = ["IDSL", "Medrax"]
    for name in project_names:
        exists = db.fetch_one("SELECT 1 FROM project WHERE project_name = %s", (name,))
        if not exists:
            project_id = str(uuid.uuid4())
            db.execute_query(
                "INSERT INTO project (project_id, project_name) VALUES (%s, %s)",
                (project_id, name)
            )
            logging.info(f"Project '{name}' created with ID {project_id}.")

    # Insert default admin user if no users exist
    result = db.fetch_one("SELECT COUNT(*) FROM users")
    if result["count"] == 0:
        user_id = str(uuid.uuid4())
        hashed_password = hash_password("admin")

        # Get the IDSL project ID for admin
        project = db.fetch_one("SELECT project_id FROM project WHERE project_name = %s", ("IDSL",))
        project_id = project["project_id"]

        db.execute_query(
            "INSERT INTO users (user_id, username, password_hash, project_id) VALUES (%s, %s, %s, %s)",
            (user_id, "admin", hashed_password, project_id)
        )
        logging.info("Admin user created with default 'IDSL' project.")

@app.get("/health")
def health():
    return {"status": "Service is running!"}

# Swagger UI Bearer token support
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
