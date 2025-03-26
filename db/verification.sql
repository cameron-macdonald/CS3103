CREATE TABLE verification_tokens (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(userID) ON DELETE CASCADE
);

DELIMITER //

CREATE PROCEDURE save_verification_token(
    IN p_user_id INT,
    IN p_token VARCHAR(64),
    IN p_expires_at TIMESTAMP
)
BEGIN
    INSERT INTO verification_tokens (user_id, token, expires_at)
    VALUES (p_user_id, p_token, p_expires_at);
END //

DELIMITER ;

DELIMITER //

CREATE PROCEDURE get_verification_token(
    IN p_user_id INT,
    IN p_token VARCHAR(64)
)
BEGIN
    SELECT user_id, token, expires_at
    FROM verification_tokens
    WHERE user_id = p_user_id AND token = p_token;
END //

DELIMITER ;


DELIMITER //

CREATE PROCEDURE mark_email_verified(IN p_user_id INT)
BEGIN
    UPDATE users
    SET email_verified = TRUE
    WHERE userID = p_user_id;
END //

DELIMITER ;
