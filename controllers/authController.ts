import { Request, Response } from 'express';
import pool from '../config/db';
import { hashPassword, comparePassword } from '../utils/password';
import { generateToken } from '../utils/jwt';
import { authenticateToken } from '../middlewares/authMiddleware';
import { AuthenticatedRequest } from '../models/types';

// 注册接口
export const register = async (req: Request, res: Response) => {
    const { username, uid, firstName, lastName, graduationYear, interiorEmail, exteriorEmail, password } = req.body;

    // 检查请求字段的有效性
    if (!username || !uid || !firstName || !lastName || !graduationYear || !password) {
        return res.status(400).json({ message: '所有字段都是必填的' });
    }

    try {
        const hashedPassword = await hashPassword(password);
        pool.query(
            'INSERT INTO users (username, uid, first_name, last_name, graduation_year, interior_email, exterior_email, password) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [username, uid, firstName, lastName, graduationYear, interiorEmail, exteriorEmail, hashedPassword],
            (error, results) => {
                if (error) {
                    return res.status(500).json({ message: '注册失败', error });
                }
                res.status(201).json({ message: '注册成功' });
            }
        );
    } catch (error) {
        res.status(500).json({ message: '服务器错误', error });
    }
};

// 登录接口
export const login = async (req: Request, res: Response) => {
    const { identifier, password, ip, ua, lang, screenSize } = req.body;

    if (!identifier || !password) {
        return res.status(400).json({ error: 'Identifier and password are required.' });
    }

    pool.query(
        'SELECT * FROM users WHERE (username = ? OR interior_email = ? OR exterior_email = ? OR uid = ?) AND is_deleted = 0',
        [identifier, identifier, identifier, identifier],
        async (error, results: any) => {
            if (error) {
                return res.status(500).json({ message: '登录失败', error });
            }

            if (results.length === 0) {
                return res.status(401).json({ error: 'Invalid identifier or password.' });
            }

            const user = results[0];

            const isPasswordValid = await comparePassword(password, user.password);
            if (!isPasswordValid) {
                return res.status(401).json({ error: 'Invalid identifier or password.' });
            }

            const accessToken = generateToken(user.id, user.uid, process.env.JWT_SECRET as string, '15d', user.isAdmin);

            // 查 device_info 表中是否存在相同 uid 和 device_UA 的记录
            pool.query(
                'SELECT * FROM device_info WHERE uid = ? AND device_UA = ?',
                [user.uid, ua],
                (error, results: any) => {
                    if (error) {
                        console.error('Failed to query device info:', error);
                    } else if (results.length > 0) {
                        const deviceInfo = results[0];
                    } else {
                        pool.query(
                            'INSERT INTO device_info (uid, device_UA, device_lang, device_screen_size) VALUES (?, ?, ?, ?)',
                            [user.uid, ua, lang, screenSize],
                            (error) => {
                                if (error) {
                                    console.error('Failed to insert device info:', error);
                                }
                            }
                        );
                    }
                }
            );

            // 更新 users 表中的设备信息字段
            pool.query(
                'UPDATE users SET latest_ip = ?, device_UA = ?, device_lang = ?, device_screen_size = ? WHERE uid = ?',
                [ip, ua, lang, screenSize, user.uid],
                (error) => {
                    if (error) {
                        console.error('Failed to update user device info:', error);
                    }
                }
            );

            res.json({ accessToken });
        }
    );
};

// 刷新 Token 函数
export const refreshToken = [
    authenticateToken,
    (req: AuthenticatedRequest, res: Response) => {
        if (!req.user) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const newAccessToken = generateToken(req.user.id, req.user.uid, process.env.JWT_SECRET!, process.env.JWT_EXPIRATION!, req.user.isAdmin);
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

