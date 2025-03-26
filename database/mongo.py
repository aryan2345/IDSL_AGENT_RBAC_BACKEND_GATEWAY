from typing import Dict, List
from bson import ObjectId
from fastapi import HTTPException
from pymongo import MongoClient
import os

class MongoDB:
    def __init__(self, db_url: str = None, db_name: str = "mydb", collection_name: str = "chats"):
        self.db_url = db_url or os.getenv("MONGO_URL")  # Default to environment variable if not passed
        self.client = MongoClient(self.db_url)
        self.db = self.client[db_name]  # Access the database
        self.collection = self.db[collection_name]

    def create_new_chat(self, chat_id: str) -> str:
        """
        Create a new chat with the given chat_id. The chat_content is initialized as an empty list.

        Args:
            chat_id (str): The unique identifier for the new chat.

        Returns:
            str: The chat_id of the newly created chat.
        """
        try:
            # Prepare the new chat document with empty chat_content
            new_chat = {
                "_id": ObjectId(chat_id),  # Use the provided chat_id as the _id
                "chat_content": []  # Initialize with an empty list
            }

            # Insert the new chat document into the collection
            result = self.collection.insert_one(new_chat)

            return str(result.inserted_id)

        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error creating new chat: {str(e)}")

    def insert_chat(self, chat_id: str, new_message: Dict) -> str:
        """
        Append a new message to an existing chat conversation (identified by chat_id).

        Args:
            chat_id (str): The unique identifier for the chat.
            new_message (Dict): The new message (in JSON format) to be appended to the chat.

        Returns:
            str: The chat_id of the updated chat.
        """
        try:
            result = self.collection.update_one(
                {"_id": ObjectId(chat_id)},  # Find the document by chat_id
                {"$push": {"chat_content": new_message}},  # Append the new message to the chat_content array
            )

            # If no document is matched, return an error
            if result.matched_count == 0:
                raise HTTPException(status_code=404, detail="Chat not found")

            return chat_id  # Return the chat_id of the updated chat

        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error appending message to chat: {str(e)}")

    def get_chat_by_id(self, chat_id: str) -> Dict:
        """
        Retrieve a chat by its chat_id.

        Args:
            chat_id (str): The chat_id of the chat to retrieve.

        Returns:
            Dict: The chat document containing chat_id and chat_content.
        """
        try:
            chat = self.collection.find_one({"_id": ObjectId(chat_id)})
            if chat:
                return {"chat_id": str(chat["_id"]), "chat_content": chat["chat_content"]}

            else:
                raise HTTPException(status_code=404, detail="Chat not found")

        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error retrieving chat: {str(e)}")

    def get_all_chats(self) -> List[Dict]:
        """
        Retrieve all chats from the collection.

        Returns:
            List[Dict]: A list of all chat documents, each containing chat_id and chat_content.
        """
        try:
            chats = self.collection.find()
            return [
                {"chat_id": str(chat["_id"]), "chat_content": chat["chat_content"]}
                for chat in chats
            ]

        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error retrieving chats: {str(e)}")


