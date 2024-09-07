import mysql from 'mysql2';
import dotenv from 'dotenv';

// import .env variables
dotenv.config();

const pool = mysql.createPool({
    connectionLimit: 100, // Maximum of connections
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

// Keep the connection alive periodically
setInterval(() => {
    pool.query('SELECT 1', (err) => {
        if (err) {
            console.error('Error with keep-alive query:', err);
        } else {
            console.log('Keep-alive query executed successfully.');
        }
    });
}, 3600000); // execute every hour

export default pool;