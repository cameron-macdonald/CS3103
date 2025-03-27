-- User Table
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    userID INT AUTO_INCREMENT PRIMARY KEY,
    emailAdress VARCHAR(255) UNIQUE NOT NULL,
    firstName VARCHAR(255) NOT NULL,
    lastName VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    dateCreated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Present List Table
DROP TABLE IF EXISTS presentlists;
CREATE TABLE presentlists (
    presentListID INT AUTO_INCREMENT PRIMARY KEY,
    userID INT,
    name VARCHAR(255) NOT NULL,
    occasion VARCHAR(255),
    dateCreated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (userID) REFERENCES users(userID) ON DELETE CASCADE
);

-- Present Table
DROP TABLE IF EXISTS presents;
CREATE TABLE presents (
    presentID INT AUTO_INCREMENT PRIMARY KEY,
    listID INT,
    presentName VARCHAR(255) NOT NULL,
    description VARCHAR(511),
    status TINYINT,
    priority TINYINT,
    FOREIGN KEY (listID) REFERENCES presentlists(presentListID) ON DELETE CASCADE
);

--verification_tokens table
CREATE TABLE verification_tokens (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(userID) ON DELETE CASCADE
);
