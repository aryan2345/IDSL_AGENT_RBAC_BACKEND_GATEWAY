import uuid
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from database.mongo import MongoDB
from schema.models import ChatRequest, UpdateChatRequest
from utils.helper import verify_token, db, log_audit

chat_router = APIRouter()
mongo = MongoDB()
logger = logging.getLogger(__file__)

@chat_router.get("/chat/get_conversations")
async def get_conversations(current_user: dict = Depends(verify_token)):
    try:
        query = """
            SELECT chat_id, chat_name
            FROM idsl_chats
            WHERE user_id = %s
        """
        chats = db.fetch_all(query, (current_user["user_id"],))
        log_audit(current_user["user_id"], "/chat/get_conversations", 200, "Fetched user chats")
        return chats
    except Exception as e:
        logger.error(f"Error in get_conversations: {e}")
        log_audit(current_user["user_id"], "/chat/get_conversations", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Error fetching conversations")

@chat_router.post("/chat/create_conversation")
async def create_conversation(request: ChatRequest, current_user: dict = Depends(verify_token)):
    chat_id = str(uuid.uuid4())

    # Insert into PostgreSQL
    try:
        db.execute_query(
            "INSERT INTO idsl_chats (chat_id, user_id, chat_name, chat_content) VALUES (%s, %s, %s, %s)",
            (chat_id, current_user["user_id"], request.chat_name, '')
        )
        log_audit(current_user["user_id"], "/chat/create_conversation", 201, f"Created chat {chat_id}")
    except Exception as e:
        logger.error(f"PostgreSQL error in create_conversation: {e}")
        log_audit(current_user["user_id"], "/chat/create_conversation", 500, f"PostgreSQL error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error inserting chat into PostgreSQL: {str(e)}")

    # Insert into MongoDB
    try:
        mongo.create_new_chat(chat_id)
    except HTTPException as e:
        logger.error(f"MongoDB error in create_conversation: {e}")
        log_audit(current_user["user_id"], "/chat/create_conversation", 500, f"MongoDB error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error creating chat in MongoDB: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error in MongoDB creation: {e}")
        log_audit(current_user["user_id"], "/chat/create_conversation", 500, f"Unexpected MongoDB error: {str(e)}")
        raise HTTPException(status_code=500, detail="Unexpected error creating chat in MongoDB")

    return {"message": "Chat created successfully", "chat_id": chat_id}

@chat_router.get("/chat/get_conversation_history")
async def get_conversation_history(request: ChatRequest, current_user: dict = Depends(verify_token)):
    try:
        check = db.fetch_one(
            "SELECT 1 FROM idsl_chats WHERE chat_id = %s AND user_id = %s",
            (request.chat_id, current_user["user_id"])
        )
        if not check:
            log_audit(current_user["user_id"], "/chat/get_conversation_history", 403, "Access denied to chat")
            raise HTTPException(status_code=403, detail="Access denied to this chat")

        chat = mongo.get_chat_by_id(request.chat_id)
        log_audit(current_user["user_id"], "/chat/get_conversation_history", 200, f"Fetched chat {request.chat_id}")
        return {"chat_id": request.chat_id, "chat_content": chat.get("chat_content", [])}
    except HTTPException as e:
        logger.error(f"HTTP error in get_conversation_history: {e}")
        log_audit(current_user["user_id"], "/chat/get_conversation_history", e.status_code, f"Error: {e.detail}")
        raise
    except Exception as e:
        logger.error(f"General error in get_conversation_history: {e}")
        log_audit(current_user["user_id"], "/chat/get_conversation_history", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error fetching chat history: {str(e)}")

@chat_router.post("/chat/update_conversation")
async def update_conversation(request: UpdateChatRequest, current_user: dict = Depends(verify_token)):
    try:
        check = db.fetch_one(
            "SELECT 1 FROM idsl_chats WHERE chat_id = %s AND user_id = %s",
            (request.chat_id, current_user["user_id"])
        )
        if not check:
            log_audit(current_user["user_id"], "/chat/update_conversation", 403, "Access denied to update chat")
            raise HTTPException(status_code=403, detail="Access denied to update this chat")

        for chat_element in request.chat:
            mongo.insert_chat(request.chat_id, chat_element)

        log_audit(current_user["user_id"], "/chat/update_conversation", 200, f"Updated chat {request.chat_id}")
        return {"message": "Chat updated successfully"}
    except HTTPException as e:
        logger.error(f"HTTP error in update_conversation: {e}")
        log_audit(current_user["user_id"], "/chat/update_conversation", e.status_code, f"Error: {e.detail}")
        raise
    except Exception as e:
        logger.error(f"General error in update_conversation: {e}")
        log_audit(current_user["user_id"], "/chat/update_conversation", 500, f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error updating conversation: {str(e)}")
