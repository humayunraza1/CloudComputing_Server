const sql = require('mssql');
const fs = require('fs');
const path = require('path');
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

async function initializeDatabase() {
    try {
        // Connect to the database
        await sql.connect(dbConfig);
        console.log('Connected to database');

        // Read the schema file
        const schemaPath = path.join(__dirname, 'schema.sql');
        const schema = fs.readFileSync(schemaPath, 'utf8');

        // Split the schema into individual statements
        const statements = schema
            .split(';')
            .filter(statement => statement.trim() !== '');

        // Execute each statement
        for (const statement of statements) {
            try {
                await sql.query(statement);
                console.log('Executed statement successfully');
            } catch (err) {
                console.error('Error executing statement:', err);
                console.error('Statement:', statement);
            }
        }

        console.log('Database initialization completed');
    } catch (err) {
        console.error('Database initialization failed:', err);
    } finally {
        await sql.close();
    }
}

// Run the initialization
initializeDatabase(); 