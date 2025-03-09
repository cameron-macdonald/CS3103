-- Get all presents
DELIMITER //
DROP PROCEDURE IF EXISTS getPresents //
CREATE PROCEDURE getPresents()
BEGIN
    SELECT * FROM presents;
END //
DELIMITER ;

-- Get all presents by userID
-- DELIMITER //
-- DROP PROCEDURE IF EXISTS getPresentsByUserID //
-- CREATE PROCEDURE getPresentsByUserID(IN userIDIn INT)
-- BEGIN
--     SELECT * FROM presents NATURAL JOIN presentlists NATURAL JOIN users
--     WHERE userID = userIDIn;
-- END //
-- DELIMITER ;

-- Get presents by ID
DELIMITER //
DROP PROCEDURE IF EXISTS getPresentByID //
CREATE PROCEDURE getPresentByID(IN presentIDIn INT)
BEGIN
    SELECT * FROM presents WHERE presentID = presentIDIn;
END //
DELIMITER ;

-- Get presents by userID and ID
DELIMITER //
DROP PROCEDURE IF EXISTS getPresentByUserID //
CREATE PROCEDURE getPresentByUserID(IN userIDIn INT, IN presentIDIn INT)
BEGIN
    SELECT * FROM presents NATURAL JOIN presentlists NATURAL JOIN users 
    WHERE presentID = presentIDIn AND userID = userIDIn;
END //
DELIMITER ;

-- Get presents by optional parameters
DELIMITER //
DROP PROCEDURE IF EXISTS getPresentsBy //
CREATE PROCEDURE getPresentsBy(IN presentNameIn VARCHAR(255), IN descriptionIn VARCHAR(511), IN statusIn TINYINT, IN priorityIn TINYINT)
BEGIN
    SELECT * FROM presents
    WHERE (presentName = presentNameIn OR presentNameIn IS NULL)
    AND (description = descriptionIn OR descriptionIn IS NULL)
    AND (status = statusIn OR statusIn IS NULL)
    AND (priority = priorityIn OR priorityIn IS NULL);
END //
DELIMITER ;

-- Add a present
DELIMITER //
DROP PROCEDURE IF EXISTS addPresent //
CREATE PROCEDURE addPresent(IN presentNameIn VARCHAR(255), IN descriptionIn VARCHAR(511), IN statusIn TINYINT, IN priorityIn TINYINT)
BEGIN
    INSERT INTO presents (presentName, description, status, priority)
    VALUES (presentNameIn, descriptionIn, statusIn, priorityIn);
END //
DELIMITER ;

-- Delete a present
DELIMITER //
DROP PROCEDURE IF EXISTS deletePresent //
CREATE PROCEDURE deletePresent(IN presentIDIn INT)
BEGIN
    DELETE FROM presents WHERE presentID = presentIDIn;
END //
DELIMITER ;

-- Update a present
DELIMITER //
DROP PROCEDURE IF EXISTS updatePresent //
CREATE PROCEDURE updatePresent(
    IN presentIDIn INT, 
    IN listIDIn INT, 
    IN presentNameIn VARCHAR(255), 
    IN descriptionIn VARCHAR(511), 
    IN statusIn TINYINT, 
    IN priorityIn TINYINT)
BEGIN
    UPDATE presents SET listID = listIDIn, presentName = presentNameIn, description = descriptionIn, 
        status = statusIn, priority = priorityIn
    WHERE presentID = presentIDIn;
    SELECT * FROM presents WHERE presentID = presentIDIn;
END //
DELIMITER ;
