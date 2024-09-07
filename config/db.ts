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
    const startTime = new Date();
    pool.query('SELECT 1', (err) => {
        const endTime = new Date();
        const executionTime = endTime.getTime() - startTime.getTime();
        if (err) {
            console.error(`[${startTime.toISOString()}] Error with keep-alive query:`, err);
        } else {
            console.log(`[${startTime.toISOString()}] Keep-alive query executed successfully in ${executionTime}ms.`);
        }
    });
}, 3600000); // execute every hour

export default pool;