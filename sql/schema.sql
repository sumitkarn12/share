DROP TABLE IF EXISTS Users;
CREATE TABLE IF NOT EXISTS Users (
    id integer not null primary key autoincrement,
    email varchar(52) not null unique,
    password  varchar(52) not null,
    email_verified boolean default false,
    verification_code varchar(6) not null,
    created_at datetime default current_timestamp
);
