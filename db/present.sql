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

CREATE PROCEDURE addPresent(
    IN listID INT, 
    IN pName VARCHAR(255), 
    IN pDescription VARCHAR(511), 
    IN pStatus TINYINT, 
    IN pPriority TINYINT
)
BEGIN
    INSERT INTO Presents (presentListID, presentName, description, status, priority)
    VALUES (listID, pName, pDescription, pStatus, pPriority);
END $$

DELIMITER ;
