DELIMITER //
CREATE TABLE Presents (
    presentID INT(11) NOT NULL AUTO_INCREMENT PRIMARY KEY,
    presentListID INT(11) NOT NULL,
    presentName VARCHAR(255) NOT NULL,
    description VARCHAR(511),
    status TINYINT DEFAULT 0,  -- 0 = not received, 1 = received
    priority TINYINT DEFAULT 1, -- Priority level (e.g., 1 = low, 2 = medium, 3 = high)
    FOREIGN KEY (presentListID) 
    REFERENCES presentlists(presentListID) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;


DELIMITER $$
CREATE PROCEDURE getPresentsByListID(IN listID INT)
BEGIN
    SELECT presentID, presentName, description, status, priority
    FROM Presents
    WHERE presentListID = listID;
END $$
DELIMITER ;

DELIMITER $$
CREATE PROCEDURE getPresents()
BEGIN
    SELECT * FROM Presents;
END $$
DELIMITER ;

DELIMITER $$
CREATE PROCEDURE getPresentByID(IN presentIDIn INT)
BEGIN
    SELECT * FROM Presents WHERE presentID = presentIDIn;
END $$
DELIMITER ;

DELIMITER $$
CREATE PROCEDURE addPresent(
    IN listID INT, 
    IN pName VARCHAR(255), 
    IN descriptionIn VARCHAR(511), 
    IN statusIn TINYINT, 
    IN priorityIn TINYINT
)
BEGIN
    INSERT INTO Presents (presentListID, presentName, description, status, priority)
    VALUES (listID, pName, descriptionIn, statusIn, priorityIn);
END $$
DELIMITER ;

DELIMITER //
DROP PROCEDURE IF EXISTS deletePresent //
CREATE PROCEDURE deletePresent(IN presentIDIn INT)
BEGIN
    DELETE FROM Presents WHERE presentID = presentIDIn;
END //
DELIMITER ;

DELIMITER $$
CREATE PROCEDURE updatePresent(IN presentNameIn VARCHAR(255), IN descriptionIn TEXT, IN statusIn BOOLEAN, IN priorityIn INT, IN presentIDIn INT)
BEGIN
    UPDATE Presents
    SET presentName = presentNameIn,
        description = descriptionIn,
        status = statusIn,
        priority = priorityIn
    WHERE presentID = presentIDIn;
END $$
DELIMITER ;

DELIMITER $$
DROP PROCEDURE IF EXISTS searchPresents $$
CREATE PROCEDURE searchPresents(
    IN presentNameIn VARCHAR(255), 
    IN descriptionIn TEXT, 
    IN statusIn BOOLEAN, 
    IN priorityIn INT, 
    IN presentListIDIn INT
)
BEGIN
    SELECT * FROM Presents
    WHERE 
        (presentNameIn IS NULL OR presentName = presentNameIn) AND
        (descriptionIn IS NULL OR description = descriptionIn) AND
        (statusIn IS NULL OR status = statusIn) AND
        (priorityIn IS NULL OR priority = priorityIn) AND
        (presentListIDIn IS NULL OR presentListID = presentListIDIn);
END $$

DELIMITER ;
