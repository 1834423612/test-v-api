CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    uid VARCHAR(20) NOT NULL UNIQUE,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    graduation_year INT NOT NULL,
    interior_email VARCHAR(100) NOT NULL COMMENT 'School Email',
    exterior_email VARCHAR(100) NOT NULL COMMENT 'Personal Email',
    password VARCHAR(255) NOT NULL,
    isAdmin TINYINT(1) DEFAULT 0 COMMENT 'Identity user permission\r\n"0" - Normal User\r\n"1" - Admin Global User\r\n"2" - Permitted Role User',
    latest_ip VARCHAR(255) NULL COMMENT 'User latest login IP',
    device_UA VARCHAR(255) NULL COMMENT 'User device UA',
    device_lang VARCHAR(255) NULL COMMENT 'User device language',
    device_screen_size VARCHAR(255) NULL COMMENT 'User device Screen Size',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE activities_data (
    id INT NOT NULL AUTO_INCREMENT,
    uid VARCHAR(20) NOT NULL,
    activity_name VARCHAR(255) NOT NULL,
    activity_location VARCHAR(255) DEFAULT NULL,
    activity_date DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00',
    activity_description VARCHAR(255) DEFAULT NULL,
    hours INT NOT NULL DEFAULT 0,
    organizer_name VARCHAR(255) NOT NULL,
    organizer_email VARCHAR(255) DEFAULT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'Unknown',
    admin_comment VARCHAR(255) DEFAULT NULL,
    is_deleted TINYINT NOT NULL DEFAULT 0 COMMENT '"0" - means still visible\r\n"1" - means deleted',
    deleted_at DATETIME DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX (uid),
    CONSTRAINT fk_activities_data_uid FOREIGN KEY (uid) REFERENCES users (uid)
);

CREATE TABLE activities_posts (
    id INT NOT NULL AUTO_INCREMENT,
    uid VARCHAR(20) NOT NULL,
    activity_name VARCHAR(255) NOT NULL,
    activity_location VARCHAR(255) NOT NULL,
    activity_date DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00',
    activity_participate_num INT DEFAULT NULL,
    activity_description VARCHAR(255) NOT NULL,
    hours INT NOT NULL DEFAULT 0,
    organizer_name VARCHAR(255) NOT NULL,
    organizer_email VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'Unknown',
    is_deleted TINYINT NOT NULL DEFAULT 0 COMMENT '"0" - means still visible\r\n"1" - means deleted',
    deleted_at DATETIME DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX (uid),
    CONSTRAINT fk_activities_posts_uid FOREIGN KEY (uid) REFERENCES users (uid)
);

CREATE TABLE announcements (
    id INT NOT NULL AUTO_INCREMENT,
    uid VARCHAR(20) NOT NULL,
    title VARCHAR(255) DEFAULT NULL,
    context VARCHAR(255) DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT fk_announcements_uid FOREIGN KEY (uid) REFERENCES users (uid)
);

CREATE TABLE device_info (
    id INT NOT NULL AUTO_INCREMENT,
    uid VARCHAR(20) NOT NULL,
    device_UA VARCHAR(255) DEFAULT NULL,
    device_lang VARCHAR(255) DEFAULT NULL,
    device_screen_size VARCHAR(255) DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX (uid),
    CONSTRAINT fk_device_info_uid FOREIGN KEY (uid) REFERENCES users (uid)
);