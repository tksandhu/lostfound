-- Run this once in your cloud MySQL database (TiDB Cloud: use the SQL Editor).
CREATE DATABASE IF NOT EXISTS lostfound CHARACTER SET utf8mb4;
USE lostfound;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(80) NOT NULL,
  email VARCHAR(120) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE items (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  kind ENUM('lost','found') NOT NULL,
  title VARCHAR(80) NOT NULL,
  category VARCHAR(40),
  place VARCHAR(80),
  item_date DATE,
  description VARCHAR(400),
  image_data MEDIUMBLOB,
  image_type VARCHAR(40),
  resolved BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX (user_id)
);

CREATE TABLE messages (
  id INT AUTO_INCREMENT PRIMARY KEY,
  item_id INT NOT NULL,
  sender_id INT NOT NULL,
  receiver_id INT NOT NULL,
  body VARCHAR(300) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX (item_id)
);
