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






# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# FastAPI app setup
app = FastAPI()
db = PostgresSQL()

# CORS middleware for frontend (React) integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5179",
        "http://localhost:5180",
        "http://host.docker.internal:5179",
        "http://host.docker.internal:5180"
    ],
    allow_credentials= True,
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
        if os.path.exists("./database/create_tables.sql"):
            with open('./database/create_tables.sql', 'r') as sql:
                ddl = sql.read()
                for stmt in ddl.split(";"):
                    stmt = stmt.strip()
                    if stmt:
                        db.execute_query(stmt)
            logging.info("✅ Tables created (if not existing).")
        else:
            logging.error("❌ create_tables.sql not found at ./database/create_tables.sql")


        # ✅ Step 1: Get or create IDSL project
        project = db.fetch_one("SELECT project_id FROM project WHERE LOWER(project_name) = 'idsl'")
        if not project:
            idsl_project_id = str(uuid.uuid4())
            db.execute_query(
                "INSERT INTO project (project_id, project_name) VALUES (%s, %s)",
                (idsl_project_id, "IDSL")
            )
            logging.info("✅ IDSL project created.")
        else:
            idsl_project_id = project["project_id"]

        # ✅ Step 2: Check if admin exists
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

        # ✅ Step 3: Ensure admin is linked to IDSL project
        existing_link = db.fetch_one(
            "SELECT 1 FROM user_projects WHERE user_id = %s AND project_id = %s",
            (admin_user_id, idsl_project_id)
        )
        if not existing_link:
            db.execute_query(
                "INSERT INTO user_projects (user_id, project_id) VALUES (%s, %s)",
                (admin_user_id, idsl_project_id)
            )
            logging.info("✅ Linked admin to IDSL project.")
        else:
            logging.info("ℹ️ Admin already linked to IDSL.")

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
