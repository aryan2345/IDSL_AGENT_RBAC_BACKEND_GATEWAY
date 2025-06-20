CREATE TABLE IF NOT EXISTS groups (
    group_id VARCHAR PRIMARY KEY,
    group_name VARCHAR NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR PRIMARY KEY,
    username VARCHAR UNIQUE NOT NULL,
    password_hash VARCHAR NOT NULL
);

CREATE TABLE IF NOT EXISTS user_groups (
    user_id VARCHAR REFERENCES users(user_id) ON DELETE CASCADE,
    group_id VARCHAR REFERENCES groups(group_id) ON DELETE CASCADE,
    is_admin BOOLEAN DEFAULT FALSE,  -- Flag to indicate group admin
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE IF NOT EXISTS chats (
    chat_id VARCHAR PRIMARY KEY,
    chat_name VARCHAR NOT NULL,
    user_id VARCHAR REFERENCES users(user_id) ON DELETE CASCADE,
    chat_content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_sessions (
    session_id VARCHAR PRIMARY KEY,
    user_id VARCHAR NOT NULL,
    token VARCHAR NOT NULL,
    expiry_timestamp TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    endpoint VARCHAR NOT NULL,
    status_code INTEGER NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    response_summary TEXT
);

CREATE TABLE IF NOT EXISTS project (
    project_id SERIAL PRIMARY KEY,
    project_name VARCHAR NOT NULL
);

CREATE TABLE IF NOT EXISTS IDSL_users (
    user_id VARCHAR NOT NULL,
    project_id INTEGER NOT NULL,
    group_id VARCHAR NOT NULL,
    role VARCHAR NOT NULL CHECK (role IN ('group_admin', 'user')),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES project(project_id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE
);
