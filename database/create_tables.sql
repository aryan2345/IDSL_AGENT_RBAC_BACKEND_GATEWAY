-- 1. Create `project` table
CREATE TABLE IF NOT EXISTS project (
    project_id VARCHAR PRIMARY KEY,
    project_name VARCHAR NOT NULL
);

-- 2. Create `groups` table
CREATE TABLE IF NOT EXISTS groups (
    group_id VARCHAR PRIMARY KEY,
    group_name VARCHAR UNIQUE NOT NULL
);

-- 3. Create `users` table
CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR PRIMARY KEY,
    username VARCHAR UNIQUE NOT NULL,
    password_hash VARCHAR NOT NULL,
    requires_password_reset INTEGER DEFAULT 0
);

-- 4. Create `user_groups` table
CREATE TABLE IF NOT EXISTS user_groups (
    user_id VARCHAR REFERENCES users(user_id) ON DELETE CASCADE,
    group_id VARCHAR REFERENCES groups(group_id) ON DELETE CASCADE,
    is_admin BOOLEAN DEFAULT FALSE
);

-- 5. Create `idsl_chats` table
CREATE TABLE IF NOT EXISTS idsl_chats (
    chat_id VARCHAR PRIMARY KEY,
    chat_name VARCHAR NOT NULL,
    user_id VARCHAR REFERENCES users(user_id) ON DELETE CASCADE,
    chat_content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 6. Create `user_sessions` table
CREATE TABLE IF NOT EXISTS user_sessions (
    session_id VARCHAR PRIMARY KEY,
    user_id VARCHAR NOT NULL,
    token VARCHAR NOT NULL,
    expiry_timestamp TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- 7. Create `audit` table
CREATE TABLE IF NOT EXISTS audit (
    user_id VARCHAR NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    endpoint VARCHAR NOT NULL,
    status_code INTEGER NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    response_summary TEXT
);

-- 8. Create `IDSL_users` table
CREATE TABLE IF NOT EXISTS IDSL_users (
    user_id VARCHAR NOT NULL,
    group_id VARCHAR NOT NULL,
    role VARCHAR NOT NULL CHECK (role IN ('group_admin', 'user')),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE
);

-- 9. Create `MEDRAX_users` table
CREATE TABLE IF NOT EXISTS MEDRAX_users (
    user_id VARCHAR NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- 10. Create `user_projects` table
CREATE TABLE IF NOT EXISTS user_projects (
    user_id VARCHAR NOT NULL,
    project_id VARCHAR NOT NULL,
    flag INTEGER DEFAULT 0,  -- 0: active, 1: access revoked
    PRIMARY KEY (user_id, project_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES project(project_id) ON DELETE CASCADE
);

