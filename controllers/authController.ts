import { Request, Response } from 'express';
import connection from '../config/db';
import { hashPassword, comparePassword } from '../utils/password';
import { generateToken } from '../utils/jwt';
import { User } from '../models/User';


export const register = async (req: Request, res: Response) => {
    const { username, password, firstName, lastName, interiorEmail, exteriorEmail, uid, graduationYear } = req.body;

    // 检查请求字段的有效性（可以根据自己的需求进行更严格的验证）
    if (!username || !password || !firstName || !lastName || !uid || !graduationYear) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        const hashedPassword = await hashPassword(password); // 哈希处理密码

        const newUser = {
            username,
            uid,
            first_name: firstName, 
            last_name: lastName,
            graduation_year: graduationYear,
            interior_email: interiorEmail, 
            exterior_email: exteriorEmail,
            password: hashedPassword, 
        };

        // 插入用户到数据库
        connection.query('INSERT INTO users SET ?', newUser, (error) => {
            if (error) {
                console.error('Database insertion error:', error);
                return res.status(500).json({ error: 'User registration failed.' });
            }
            res.status(201).json({ message: 'User registered successfully.' });
        });
    } catch (error) {
        console.error('Registration error:', error);
        return res.status(500).json({ error: 'User registration failed.' });
    }
};

export const login = async (req: Request, res: Response) => {
    const { username, password } = req.body;

    connection.query('SELECT * FROM users WHERE username = ?', [username], async (error, results: any) => {
        if (error || results.length === 0) return res.status(404).json({ error: 'User not found.' });

        const user = results[0];

        const isPasswordValid = await comparePassword(password, user.password);
        if (!isPasswordValid) return res.status(401).json({ error: 'Invalid password.' });

        if (user.id === undefined) {
            return res.status(500).json({ error: 'User ID is not defined.' });
        }

        const accessToken = generateToken(user.id, process.env.JWT_SECRET!, process.env.JWT_EXPIRATION!);
        res.json({ accessToken });
    });
};
