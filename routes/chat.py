import uuid
import logging
from fastapi import APIRouter, Depends, HTTPException

from database.mongo import MongoDB
from schema.models import ChatRequest, UpdateChatRequest
from utils.helper import verify_token, db

chat_router = APIRouter()
mongo = MongoDB()
logger = logging.getLogger(__file__)

@chat_router.get("/chat/get_conversations")
async def get_conversations(current_user: dict = Depends(verify_token)):
    query = """
        SELECT chat_id, chat_name
        FROM chats
        WHERE user_id = %s
        """
    chats = db.fetch_all(query, (current_user["user_id"],))

    # Return the chats (could be an empty list if no chats found)
    return chats

@chat_router.post("/chat/create_conversation")
async def create_conversation(request: ChatRequest, current_user: dict = Depends(verify_token)):
    chat_id = str(uuid.uuid4())

    # Insert a new entry in the PostgreSQL 'chats' table for the user
    try:
        db.execute_query(
            "INSERT INTO chats (chat_id, user_id, chat_name) VALUES (%s, %s, %s)",
            (chat_id, current_user["user_id"], request.chat_name)
        )

    except Exception as e:
        logger.error(e)
        raise HTTPException(status_code=500, detail=f"Error inserting chat into PostgreSQL: {str(e)}")

    try:
        mongo.create_new_chat(chat_id)  # This creates the MongoDB entry with an empty chat_content list

    except HTTPException as e:
        logger.error(e)
        raise HTTPException(status_code=500, detail=f"Error creating chat in MongoDB: {str(e)}")

        # Return the chat_id and confirmation message
    return {"message": "Chat created successfully", "chat_id": chat_id}

@chat_router.get("/chat/get_conversation_history")
async def get_conversation_history(request: ChatRequest ,current_user: dict = Depends(verify_token)):
    try:
        # Fetch the chat content for the given chat_id from MongoDB
        chat = mongo.get_chat_by_id(request.chat_id)
        return {"chat_id": request.chat_id, "chat_content": chat["chat_content"]}

    except HTTPException as e:
        logger.error(e)
        # If an error occurs (e.g., chat not found), raise HTTPException with appropriate status
        raise HTTPException(status_code=e.status_code, detail=e.detail)


@chat_router.post("/chat/update_conversation")
async def update_conversation(request: UpdateChatRequest, current_user: dict = Depends(verify_token)):
    try:
        new_chat = request.chat
        for chat_element in new_chat:
            mongo.insert_chat(request.chat_id, chat_element)

    except HTTPException as e:
        logger.error(e)
        raise HTTPException(status_code=e.status_code, detail=e.detail)