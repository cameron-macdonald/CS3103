-- Get all present lists
DELIMITER //
DROP PROCEDURE IF EXISTS getLists //
CREATE PROCEDURE getLists()
BEGIN
    SELECT * FROM presentlists;
END //
DELIMITER ;

-- Get present list by ID
DELIMITER //
DROP PROCEDURE IF EXISTS getListByID //
CREATE PROCEDURE getListByID(IN presentListIDIn INT)
BEGIN
    SELECT * FROM presentlists WHERE presentListID = presentListIDIn;
END //
DELIMITER ;

-- Get presents by userID andID
DELIMITER //
DROP PROCEDURE IF EXISTS getListByUserID //
CREATE PROCEDURE getListByUserID(IN presentListIDIn INT, IN userIDIn INT)
BEGIN
    SELECT * FROM presentlists NATURAL JOIN users WHERE presentListID = presentListIDIn AND userID = userIDIn;
END //
DELIMITER ;

-- Get present lists by optional parameters
DELIMITER //
DROP PROCEDURE IF EXISTS getListsBy //
CREATE PROCEDURE getListsBy(IN occasionIn VARCHAR(255), IN nameIn VARCHAR(255), IN dateCreatedIn DATE)
BEGIN
    SELECT * FROM presentlists
    WHERE (occasion = occasionIn OR occasionIn IS NULL)
    AND (name = nameIn OR nameIn IS NULL)
    AND (dateCreated = dateCreatedIn OR dateCreatedIn IS NULL);
END //
DELIMITER ;

-- Add a present list
DELIMITER //
DROP PROCEDURE IF EXISTS addList //
CREATE PROCEDURE addList(IN nameIn VARCHAR(255), IN occasionIn VARCHAR(255))
BEGIN
    INSERT INTO presentlists (name, occasion, dateCreated) VALUES (nameIn, occasionIn, NOW());
END //
DELIMITER ;

-- Delete a present list
DELIMITER //
DROP PROCEDURE IF EXISTS deleteList //
CREATE PROCEDURE deleteList(IN listIDIn INT)
BEGIN
    DELETE FROM presentlists WHERE presentListID = listIDIn;
END //
DELIMITER ;

-- Update a present list
DELIMITER //
DROP PROCEDURE IF EXISTS updateList //
CREATE PROCEDURE updateList(
    IN listIDIn INT, 
    IN nameIn VARCHAR(255), 
    IN occasionIn VARCHAR(255))
BEGIN
    UPDATE presentlists SET name = nameIn, occasion = occasionIn WHERE presentListID = listIDIn;
END //
DELIMITER ;