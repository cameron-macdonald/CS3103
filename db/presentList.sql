DELIMITER $$

CREATE PROCEDURE getListsByUserID(IN uID INT)
BEGIN
    SELECT presentListID, userID, name, occasion, dateCreated
    FROM presentlists
    WHERE userID = uID;
END $$

DELIMITER ;
