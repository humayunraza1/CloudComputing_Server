require('dotenv').config();

const dbConfig = {
    user: 'humayunr',
    password: process.env.DB_PASSWORD,
    server: 'iba-cloud-db.database.windows.net',
    database: 'store-db',
    options: {
        encrypt: true,
        trustServerCertificate: false,
    },
};

module.exports = {
    dbConfig
}; 