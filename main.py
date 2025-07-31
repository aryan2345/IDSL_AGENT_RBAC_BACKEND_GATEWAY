import logging
import os
import uuid
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from routes.login import login_router
from routes.data import data_router
from routes.chat import chat_router
from database.postgres import PostgresSQL
from utils.helper import hash_password
from fastapi.openapi.utils import get_openapi
import pathlib

db = PostgresSQL()

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# FastAPI app setup
app = FastAPI()

# CORS middleware for frontend (React) integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5179",
        "http://localhost:5180",
        "http://host.docker.internal:5179",
        "http://host.docker.internal:5180"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include route modules
app.include_router(login_router)
app.include_router(data_router)
app.include_router(chat_router)


@app.on_event("startup")
async def startup():
    try:
        # ✅ Step 0: Create tables from create_tables.sql
        sql_file_path = pathlib.Path("database/create_tables.sql")
        if sql_file_path.exists():
            with open(sql_file_path, "r") as file:
                sql_statements = file.read()

            for statement in sql_statements.strip().split(";"):
                if statement.strip():
                    db.execute_query(statement.strip() + ";")
            logging.info("✅ Tables created or already exist.")
        else:
            logging.error("❌ create_tables.sql not found at ./database/create_tables.sql")

        # ✅ Step 1: Ensure admin user exists
        result = db.fetch_one("SELECT user_id FROM users WHERE username = 'admin'")
        if not result:
            admin_user_id = str(uuid.uuid4())
            hashed_password = hash_password("admin")
            db.execute_query(
                "INSERT INTO users (user_id, username, password_hash) VALUES (%s, %s, %s)",
                (admin_user_id, "admin", hashed_password)
            )
            logging.info("✅ Admin user created.")
        else:
            admin_user_id = result["user_id"]
            logging.info("ℹ️ Admin user already exists.")

        # ✅ Step 2: Create and link multiple hardcoded projects
        project_names = ["IDSL", "MEDRAX"]

        for project_name in project_names:
            # Check if project exists
            project = db.fetch_one(
                "SELECT project_id FROM project WHERE LOWER(project_name) = %s",
                (project_name.lower(),)
            )
            if not project:
                project_id = str(uuid.uuid4())
                db.execute_query(
                    "INSERT INTO project (project_id, project_name) VALUES (%s, %s)",
                    (project_id, project_name)
                )
                logging.info(f"✅ {project_name} project created.")
            else:
                project_id = project["project_id"]
                logging.info(f"ℹ️ {project_name} project already exists.")

            # Link admin to the project
            existing_link = db.fetch_one(
                "SELECT 1 FROM user_projects WHERE user_id = %s AND project_id = %s",
                (admin_user_id, project_id)
            )
            if not existing_link:
                db.execute_query(
                    "INSERT INTO user_projects (user_id, project_id) VALUES (%s, %s)",
                    (admin_user_id, project_id)
                )
                logging.info(f"✅ Linked admin to {project_name} project.")
            else:
                logging.info(f"ℹ️ Admin already linked to {project_name}.")

    except Exception as e:
        logging.error(f"❌ Startup error: {str(e)}")


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