-- Get all users (DONE)
DELIMITER //
DROP PROCEDURE IF EXISTS getUsers //
CREATE PROCEDURE getUsers()
BEGIN
    SELECT * FROM users;
END //
DELIMITER ;

-- Get user by ID (DONE)
DELIMITER //
DROP PROCEDURE IF EXISTS getUserByID //
CREATE PROCEDURE getUserByID(IN userIDIn INT)
BEGIN
    SELECT * FROM users WHERE userID = userIDIn;
END //
DELIMITER ;

-- Get users by optional parameters(DONE)
DELIMITER //

DROP PROCEDURE IF EXISTS getUsersBy //

CREATE PROCEDURE getUsersBy(
    IN firstNameIn VARCHAR(255), 
    IN lastNameIn VARCHAR(255), 
    IN emailAdressIn VARCHAR(255), 
    IN dateCreatedIn DATE
)
BEGIN
    SELECT * FROM users
    WHERE (firstName = firstNameIn OR firstNameIn IS NULL OR firstNameIn = '')
    AND (lastName = lastNameIn OR lastNameIn IS NULL OR lastNameIn = '')
    AND (emailAdress = emailAdressIn OR emailAdressIn IS NULL OR emailAdressIn = '')
    AND (dateCreated = dateCreatedIn OR dateCreatedIn IS NULL);
END //

DELIMITER ;


-- Add a user (DONE)
DELIMITER //

DROP PROCEDURE IF EXISTS addUser //

CREATE PROCEDURE addUser(
    IN emailAdressIn VARCHAR(255), 
    IN firstNameIn VARCHAR(255), 
    IN lastNameIn VARCHAR(255), 
    IN usernameIn VARCHAR(255),
    IN passwordIn VARCHAR(255)
)
BEGIN
    INSERT INTO users (emailAdress, firstName, lastName, username, password, dateCreated)
    VALUES (emailAdressIn, firstNameIn, lastNameIn, usernameIn, passwordIn, NOW());

    SELECT LAST_INSERT_ID() as id;  -- Return the newly created user ID
END //

DELIMITER ;

-- Delete a user (DONE)
DELIMITER //
DROP PROCEDURE IF EXISTS deleteUser //
CREATE PROCEDURE deleteUser(IN userIDIn INT)
BEGIN
    DELETE FROM users WHERE userID = userIDIn;
END //
DELIMITER ;

-- Update a user
DELIMITER //
DROP PROCEDURE IF EXISTS updateUser //
CREATE PROCEDURE updateUser(IN userIDIn INT, IN emailAdressIn VARCHAR(255), IN firstNameIn VARCHAR(255), IN lastNameIn VARCHAR(255), IN passwordIn VARCHAR(255))
BEGIN
    UPDATE users SET emailAdress = emailAdressIn, firstName = firstNameIn, lastName = lastNameIn, password = passwordIn
    WHERE userID = userIDIn;
    SELECT * FROM users WHERE userID = userIDIn;
END //
DELIMITER ;