INSERT INTO users (username, password_hash, email)
VALUES
    ('Pavel', '$2a$10$Z4J1J9aJ5.9Ntda4wjKxQu.8NHK1OB5ky/g33jlzQKv.RometKH4C', 'Pavel@example.com');

INSERT INTO user_roles (user_id, role)
VALUES
    (1, 'ROLE_USER');