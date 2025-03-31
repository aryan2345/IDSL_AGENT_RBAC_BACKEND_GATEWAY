CREATE TABLE IF NOT EXISTS groups (
    group_id VARCHAR PRIMARY KEY,
    group_name VARCHAR NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR PRIMARY KEY,
    username VARCHAR UNIQUE NOT NULL,
    password_hash VARCHAR NOT NULL,  -- Use a hashed password
    role VARCHAR CHECK(role IN ('system_admin', 'group_admin', 'user')) NOT NULL,
    group_id VARCHAR REFERENCES groups(group_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_groups (
    user_id VARCHAR REFERENCES users(user_id),
    group_id VARCHAR REFERENCES groups(group_id),
    is_admin BOOLEAN DEFAULT FALSE,  -- Flag to indicate group admin
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE IF NOT EXISTS chats (
    chat_id VARCHAR PRIMARY KEY,
    chat_name VARCHAR,
    user_id VARCHAR REFERENCES users(user_id),
    chat_content TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_sessions (
    session_id VARCHAR PRIMARY KEY,
    user_id VARCHAR NOT NULL,
    token VARCHAR NOT NULL,
    expiry_timestamp TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);