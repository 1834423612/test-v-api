import { Request, Response } from 'express';
import connection from '../config/db';
import { hashPassword, comparePassword } from '../utils/password';
import { generateToken } from '../utils/jwt';
import { User } from '../models/User';
import jwt from 'jsonwebtoken';
import { authenticateToken } from '../middlewares/authMiddleware';
import { AuthenticatedRequest } from '../models/types';

// 定义用户信息的接口
interface UserInfo {
    id: number;
    username: string;
    uid: string;
    first_name: string;
    last_name: string;
    graduation_year: number;
    isAdmin: number;
    interior_email: string;
    exterior_email: string;
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
            isAdmin: 0,
            password: hashedPassword,
        };

        // 插入用户到数据库
        connection.query('INSERT INTO users SET ?', newUser, async (error) => {
            if (error) {
                console.error('Database insertion error:', error);
                return res.status(500).json({ error: 'User registration failed.' });
            }

            // 注册成功后，自动登录并返回 JWT
            const accessToken = generateToken(newUser.uid, process.env.JWT_SECRET!, process.env.JWT_EXPIRATION!, newUser.isAdmin);
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

            const accessToken = generateToken(user.uid, process.env.JWT_SECRET!, process.env.JWT_EXPIRATION!, user.isAdmin);
            res.status(200).json({ accessToken });
        }
    );
};

// 设置管理员接口
export const setAdmin = (req: AuthenticatedRequest, res: Response) => {
    if (!req.user) {
        return res.sendStatus(401); // 如果用户未登录，返回401未授权
    }

    const { userId, isAdmin } = req.body;

    // 检查当前用户是否为管理员
    connection.query('SELECT isAdmin FROM users WHERE uid = ?', [req.user.id], (error, results) => {
        if (error) {
            console.error('Database query error:', error);
            return res.status(500).json({ error: 'Failed to check user permissions.' });
        }

        const userResults = results as UserInfo[];

        if (userResults.length === 0 || userResults[0].isAdmin !== 1) {
            return res.status(403).json({ error: 'Permission denied.' });
        }

        // 更新用户权限
        connection.query('UPDATE users SET isAdmin = ? WHERE uid = ?', [isAdmin, userId], (error) => {
            if (error) {
                console.error('Database update error:', error);
                return res.status(500).json({ error: 'Failed to update user permissions.' });
            }

            res.status(200).json({ message: 'User permissions updated successfully.' });
        });
    });
};

// 获取当前登录用户信息的接口
export const getUserInfo = (req: AuthenticatedRequest, res: Response) => {
    if (!req.user) {
        return res.sendStatus(401); // 如果用户未登录，返回401未授权
    }

    const userId = req.user.id;

    // 从数据库中获取用户信息
    // connection.query('SELECT * FROM users WHERE uid = ?', [userId], (error, results) => {
    connection.query('SELECT * FROM users WHERE uid = ?', [req.user.uid], (error, results) => {
        if (error) {
            console.error('Database query error:', error);
            return res.status(500).json({ error: 'Failed to retrieve user information.' });
        }

        const userResults = results as UserInfo[];

        if (userResults.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        const user = userResults[0];
        res.status(200).json({
            id: user.id,
            username: user.username,
            uid: user.uid,
            firstName: user.first_name,
            lastName: user.last_name,
            graduationYear: user.graduation_year,
            interiorEmail: user.interior_email,
            exteriorEmail: user.exterior_email,
        });
    });
};

// 刷新 Token 函数
export const refreshToken = [
    authenticateToken,
    (req: AuthenticatedRequest, res: Response) => {
        if (!req.user) return res.sendStatus(403); // 确保 req.user 存在

        const newAccessToken = generateToken(req.user.id, process.env.JWT_SECRET!, process.env.JWT_EXPIRATION!, req.user.isAdmin);
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


// 添加活动记录的接口
export const addActivity = (req: AuthenticatedRequest, res: Response) => {
    if (!req.user || req.user.isAdmin !== 1) {
        return res.sendStatus(403); // 如果用户不是管理员，返回403禁止访问
    }

    const { uid, activity_name, activity_date, status, organizer, hours } = req.body;

    connection.query(
        'INSERT INTO activities_data (uid, activity_name, activity_date, status, organizer, hours) VALUES (?, ?, ?, ?, ?, ?)',
        [uid, activity_name, activity_date || '1970-01-01 00:00:00', status || 'Unknown', organizer, hours || 0],
        (error, results) => {
            if (error) {
                console.error('Database insert error:', error);
                return res.status(500).json({ error: 'Failed to add activity.' });
            }

            res.status(201).json({ message: 'Activity added successfully.' });
        }
    );
};

// 修改活动记录的接口
export const updateActivity = (req: AuthenticatedRequest, res: Response) => {
    if (!req.user || req.user.isAdmin !== 1) {
        return res.sendStatus(403); // 如果用户不是管理员，返回403禁止访问
    }

    const { id, activity_name, activity_date, status, organizer, hours } = req.body;

    connection.query(
        'UPDATE activities_data SET activity_name = ?, activity_date = ?, status = ?, organizer = ?, hours = ? WHERE id = ?',
        [activity_name, activity_date || '1970-01-01 00:00:00', status, organizer, hours, id],
        (error, results) => {
            if (error) {
                console.error('Database update error:', error);
                return res.status(500).json({ error: 'Failed to update activity.' });
            }

            res.status(200).json({ message: 'Activity updated successfully.' });
        }
    );
};

// 获取活动记录的接口
export const getActivities = (req: Request, res: Response) => {
    const authHeader = req.headers['authorization'];
    let uid: string | undefined;

    if (authHeader) {
        const token = authHeader.split(' ')[1];
        try {
            const decodedToken = jwt.verify(token, process.env.JWT_SECRET as string) as any;
            uid = decodedToken.uid;
        } catch (err) {
            console.error('Token verification error:', err);
            return res.sendStatus(403); // 如果 Token 无效，返回 403 禁止访问
        }
    } else {
        // 未登录时需要提供查询参数
        uid = req.query.uid as string;
        const firstName = req.query.firstName as string;
        const lastName = req.query.lastName as string;

        if (!uid || !firstName || !lastName) {
            return res.status(400).json({ message: 'Missing required query parameters' });
        }
    }

    // 从数据库中获取活动记录
    connection.query('SELECT * FROM activities_data WHERE uid = ?', [uid], (error, results) => {
        if (error) {
            console.error('Database query error:', error);
            return res.status(500).json({ message: 'Database query error' });
        }
        res.json(results);
    });
};

// 删除活动记录的接口
export const deleteActivity = (req: AuthenticatedRequest, res: Response) => {
    if (!req.user || req.user.isAdmin !== 1) {
        return res.sendStatus(403); // 如果用户不是管理员，返回403禁止访问
    }

    const { id } = req.body;

    connection.query(
        'DELETE FROM activities_data WHERE id = ?',
        [id],
        (error, results) => {
            if (error) {
                console.error('Database delete error:', error);
                return res.status(500).json({ error: 'Failed to delete activity.' });
            }

            res.status(200).json({ message: 'Activity deleted successfully.' });
        }
    );
};
