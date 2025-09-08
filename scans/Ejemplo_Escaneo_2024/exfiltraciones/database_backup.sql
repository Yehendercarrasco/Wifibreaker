-- Backup de base de datos exfiltrado
-- Este archivo simula una base de datos extraída del sistema comprometido

CREATE DATABASE company_db;
USE company_db;

CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50),
    password_hash VARCHAR(255),
    email VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE financial_data (
    id INT PRIMARY KEY AUTO_INCREMENT,
    account_number VARCHAR(20),
    balance DECIMAL(10,2),
    transaction_date DATE
);

-- Datos de ejemplo (simulados)
INSERT INTO users (username, password_hash, email) VALUES
('admin', '5d41402abc4b2a76b9719d911017c592', 'admin@company.com'),
('user1', '098f6bcd4621d373cade4e832627b4f6', 'user1@company.com');

INSERT INTO financial_data (account_number, balance, transaction_date) VALUES
('ACC001', 50000.00, '2024-12-01'),
('ACC002', 25000.00, '2024-12-02');
