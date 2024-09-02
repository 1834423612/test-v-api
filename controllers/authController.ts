import { Request, Response } from 'express';
import connection from '../config/db';
import { hashPassword, comparePassword } from '../utils/password';
import { generateToken } from '../utils/jwt';
import { User } from '../models/User';
import jwt from 'jsonwebtoken';
import { authenticateToken } from '../middlewares/authMiddleware';

interface AuthenticatedRequest extends Request {
    user?: any;
}

// 注册接口
export const register = async (req: Request, res: Response) => {
    const { username, uid, firstName, lastName, graduationYear, interiorEmail, exteriorEmail, password } = req.body;

    // 检查请求字段的有效性
    if (!username || !uid || !firstName || !lastName || !graduationYear || !password) {
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
        connection.query('INSERT INTO users SET ?', newUser, async (error) => {
            if (error) {
                console.error('Database insertion error:', error);
                return res.status(500).json({ error: 'User registration failed.' });
            }

            // 注册成功后，自动登录并返回 JWT
            const accessToken = generateToken(newUser.uid, process.env.JWT_SECRET!, process.env.JWT_EXPIRATION!);
            res.status(201).json({ message: 'User registered successfully.', accessToken });
        });
    } catch (error) {
        console.error('Registration error:', error);
        return res.status(500).json({ error: 'User registration failed.' });
    }
};

// 登录接口
export const login = async (req: Request, res: Response) => {
    const { identifier, password } = req.body; // 使用 identifier 区分不同的登录方法

    if (!identifier || !password) {
        return res.status(400).json({ error: 'Identifier and password are required.' });
    }

    // 使用一个查询找到用户，包括 username, interior_email, exterior_email, uid
    connection.query(
        'SELECT * FROM users WHERE username = ? OR interior_email = ? OR exterior_email = ? OR uid = ?',
        [identifier, identifier, identifier, identifier],
        async (error, results: any) => {
            if (error || results.length === 0) return res.status(404).json({ error: 'User not found.' });

            const user = results[0];

            const isPasswordValid = await comparePassword(password, user.password);
            if (!isPasswordValid) return res.status(401).json({ error: 'Invalid password.' });

            const accessToken = generateToken(user.uid, process.env.JWT_SECRET!, process.env.JWT_EXPIRATION!);
            res.status(200).json({ accessToken });
        }
    );
};

// 刷新 Token 函数
export const refreshToken = [
    authenticateToken,
    (req: AuthenticatedRequest, res: Response) => {
        if (!req.user) return res.sendStatus(403); // 确保 req.user 存在

        const newAccessToken = generateToken(req.user.id, process.env.JWT_SECRET!, process.env.JWT_EXPIRATION!);
        return res.json({ accessToken: newAccessToken });
    }
];

// export const refreshToken = (req: Request, res: Response) => {
//     const token = req.headers['authorization']?.split(' ')[1];

//     if (!token) return res.sendStatus(401); // 如果没有token，返回401

//     jwt.verify(token, process.env.JWT_SECRET!, (err: any) => {
//         if (err) return res.sendStatus(403); // 如果token过期或无效，返回403

//         // 如果token有效，生成新的accessToken
//         if (req.user) { // 确保 req.user 存在
//             const newAccessToken = generateToken(req.user.id, process.env.JWT_SECRET!, process.env.JWT_EXPIRATION!);
//             return res.json({ accessToken: newAccessToken });
//         } else {
//             return res.sendStatus(403); // 如果没有用户信息，返回403
//         }
//     });
// };
