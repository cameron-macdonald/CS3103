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
 
-- Get present list by userID and listID
DELIMITER //
DROP PROCEDURE IF EXISTS getListByUserID //
CREATE PROCEDURE getListByUserID(IN userIDIn INT, IN presentListIDIn INT)
BEGIN
    SELECT * 
    FROM presentlists 
    NATURAL JOIN users 
    WHERE presentListID = presentListIDIn AND userID = userIDIn;
END //
DELIMITER ;

DELIMITER $$
CREATE PROCEDURE getListsByUserID(IN uID INT)
BEGIN
    SELECT presentListID, userID, name, occasion, dateCreated
    FROM presentlists
    WHERE userID = uID;
END $$
DELIMITER ;

 
-- Get present lists by optional parameters (userID, occasion, name, dateCreated)
DELIMITER //
DROP PROCEDURE IF EXISTS getListsBy //
CREATE PROCEDURE getListsBy(IN userIDIn INT, IN occasionIn VARCHAR(255), IN nameIn VARCHAR(255), IN dateCreatedIn DATE)
BEGIN
    SELECT * 
    FROM presentlists
    NATURAL JOIN users
    WHERE userID = userIDIn
    AND (occasion = occasionIn OR occasionIn IS NULL)
    AND (name = nameIn OR nameIn IS NULL)
    AND (dateCreated = dateCreatedIn OR dateCreatedIn IS NULL);
END //
DELIMITER ;
 
 
-- Add a present list
DELIMITER //
DROP PROCEDURE IF EXISTS addList //
CREATE PROCEDURE addList(IN userIDIn INT, IN nameIn VARCHAR(255), IN occasionIn VARCHAR(255))
BEGIN
    INSERT INTO presentlists (userID, name, occasion, dateCreated) 
    VALUES (userIDIn, nameIn, occasionIn, NOW());
    SELECT LAST_INSERT_ID() AS new_list_id;
END //
DELIMITER ;
 
-- Delete a present list
DELIMITER //
DROP PROCEDURE IF EXISTS deleteList //
CREATE PROCEDURE deleteList(IN userIDIn INT, IN listIDIn INT)
BEGIN
    DELETE FROM presentlists 
    WHERE presentListID = listIDIn AND userID = userIDIn;
END //
DELIMITER ;
 

 
-- Update a present list
DELIMITER //
DROP PROCEDURE IF EXISTS updateList //
CREATE PROCEDURE updateList(
    IN userIDIn INT,
    IN listIDIn INT, 
    IN nameIn VARCHAR(255), 
    IN occasionIn VARCHAR(255))
BEGIN
    UPDATE presentlists 
    SET name = nameIn, occasion = occasionIn 
    WHERE presentListID = listIDIn AND userID = userIDIn;
END //
DELIMITER ;


--Search 
DELIMITER $$

CREATE PROCEDURE searchPresentLists(
    IN p_presentListID INT,
    IN p_userID INT,
    IN p_name VARCHAR(255),
    IN p_occasion VARCHAR(255),
    IN p_dateCreated DATETIME
)
BEGIN
    SELECT * FROM presentlists 
    WHERE 
        (p_presentListID IS NULL OR presentListID = p_presentListID) AND
        (p_userID IS NULL OR userID = p_userID) AND
        (p_name IS NULL OR name LIKE CONCAT('%', p_name, '%')) AND
        (p_occasion IS NULL OR occasion LIKE CONCAT('%', p_occasion, '%')) AND
        (p_dateCreated IS NULL OR dateCreated >= p_dateCreated);
END $$

DELIMITER ;
