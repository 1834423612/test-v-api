import { Request, Response } from 'express';
import connection from '../config/db';
import { hashPassword, comparePassword } from '../utils/password';
import { generateToken } from '../utils/jwt';
import { User } from '../models/User';


export const register = async (req: Request, res: Response) => {
    const { username, password, firstName, lastName, interiorEmail, exteriorEmail, uid, graduationYear } = req.body;

    const hashedPassword = await hashPassword(password);
    const newUser: User = { username, password: hashedPassword, firstName, lastName, interiorEmail, exteriorEmail, uid, graduationYear };

    connection.query('INSERT INTO users SET ?', newUser, (error, results) => {
        if (error) return res.status(500).json({ error: 'User registration failed.' });
        res.status(201).json({ message: 'User registered successfully.' });
    });
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
