import express from 'express';
import dotenv from 'dotenv';
import authRoutes from './routes/authRoutes';
import bodyParser from 'body-parser';
import cors from 'cors';

dotenv.config();
const app = express();

app.use(bodyParser.json());
app.use('/api/auth', authRoutes);

// 处理 CORS
app.use(cors());
// app.use(cors({ origin: 'https://verbose-fiesta-rp5rxg49vqj3ww65-5173.app.github.dev/' })); // 允许从特定的来源发起请求


// Default homepage route, returns status code
app.get('/', (req, res) => {
    res.status(200).send('200ok! &nbsp; Welcome to the API! &nbsp; The server is running smoothly.');
});

// listen to port, default 3000
let PORT = Number(process.env.PORT) || 3000;

const server = app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

// Error handling for port already in use
server.on('error', (err: Error) => {
    if (err.message.includes('EADDRINUSE')) {
        PORT++; // Increment port by 1
        server.listen(PORT); // Try the next port
        console.log(`Port ${PORT - 1} was occupied, trying port ${PORT}...`);
    } else {
        console.error('Server error:', err);
    }
});