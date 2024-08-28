docker exec - it postgresdev psql - U postgres CREATE DATABASE cloud_auth;
CREATE USER cloud_auth_user WITH PASSWORD 'kjbv56767itufvb8gf6l7itukgvi65ccumtgvk';
GRANT ALL PRIVILEGES ON DATABASE "cloud_auth" to cloud_auth_user;
# docker exec -it postgresdev psql -d cloud_auth -U cloud_auth_user
CREATE TABLE otp_user (
    id BIGSERIAL PRIMARY KEY,
    aucCodes TEXT [] NOT NULL DEFAULT '{}',
    clientNames TEXT [] NOT NULL DEFAULT '{}',
    createdAt BIGINT NOT NULL,
    hashedOtp VARCHAR (1024) NOT NULL,
    hashedPassword VARCHAR (1024) NOT NULL,
    isOtpVerified BOOLEAN DEFAULT FALSE,
    mobileNumber BIGINT UNIQUE NOT NULL,
    otpStatus VARCHAR (20),
    timeStampsUnix BIGINT [] NOT NULL DEFAULT '{}',
    tradingHashedOtp VARCHAR (1024) NOT NULL,
    tradingHashedPassword VARCHAR (1024) NOT NULL,
    tradingIsOtpVerified BOOLEAN DEFAULT FALSE,
    tradingOtpStatus VARCHAR (20),
    updatedAt BIGINT NOT NULL,
    validUptoUnix BIGINT NOT NULL
);
CREATE TABLE auc_session (
    id BIGSERIAL PRIMARY KEY,
    authjti TEXT [] DEFAULT '{}',
    refreshjti TEXT [] DEFAULT '{}',
    mobileNumber BIGINT UNIQUE NOT NULL,
    clientName VARCHAR (512) NOT NULL,
    auc VARCHAR (512) UNIQUE NOT NULL,
    validUptoUnix BIGINT NOT NULL,
    hashedPassword VARCHAR (512) NOT NULL,
    createdAt BIGINT NOT NULL,
    updatedAt BIGINT NOT NULL
);