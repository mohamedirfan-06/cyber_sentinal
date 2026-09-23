-- Run this file as an administrative MySQL user.
-- Replace the password at execution time; never commit a real password.
CREATE USER IF NOT EXISTS 'cybersentinel_app'@'localhost' IDENTIFIED BY 'CHANGE_ME_IN_ENVIRONMENT';
GRANT SELECT, INSERT, UPDATE, DELETE ON cybersentinel.* TO 'cybersentinel_app'@'localhost';
FLUSH PRIVILEGES;
