import { Request, Response } from 'express';
import pool from '../config/db';
import { hashPassword, comparePassword } from '../utils/password';
import { generateToken, verifyToken } from '../utils/jwt';
import { User } from '../models/User';
import jwt from 'jsonwebtoken';
import { authenticateToken } from '../middlewares/authMiddleware';
import { AuthenticatedRequest } from '../models/types';
import { ResultSetHeader } from 'mysql2';

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
        'SELECT * FROM users WHERE username = ? OR interior_email = ? OR exterior_email = ? OR uid = ?',
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
                        // 如果存在且 device_lang 和 device_screen_size 不同，则不更新记录
                        if (deviceInfo.device_lang !== lang || deviceInfo.device_screen_size !== screenSize) {
                            // console.log('Device info already exists with different lang or screen size, not updating.');
                        }
                    } else {
                        // 如果不存在，则插入新的设备信息记录
                        pool.query(
                            'INSERT INTO device_info (uid, device_UA, device_lang, device_screen_size, created_at) VALUES (?, ?, ?, ?, NOW())',
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

// 设置管理员接口
export const setAdmin = (req: AuthenticatedRequest, res: Response) => {
    if (!req.user) {
        return res.sendStatus(401); // 如果用户未登录，返回401未授权
    }

    const { userId, isAdmin } = req.body;

    // 检查当前用户是否为管理员
    pool.query('SELECT isAdmin FROM users WHERE uid = ?', [req.user.id], (error, results) => {
        if (error) {
            console.error('Database query error:', error);
            return res.status(500).json({ error: 'Failed to check user permissions.' });
        }

        const userResults = results as UserInfo[];

        if (userResults.length === 0 || userResults[0].isAdmin !== 1) {
            return res.status(403).json({ error: 'Permission denied.' });
        }

        // 更新用户权限
        pool.query('UPDATE users SET isAdmin = ? WHERE uid = ?', [isAdmin, userId], (error) => {
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
    pool.query('SELECT * FROM users WHERE uid = ?', [req.user.uid], (error, results) => {
        if (error) {
            console.error('Database query error:', error);
            return res.status(500).json({ error: 'Failed to retrieve user information.' });
        }

        const userResults = results as UserInfo[];

        if (userResults.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        const user = userResults[0];
        res.status(200).json(user);
    });
};

// 刷新 Token 函数
export const refreshToken = [
    authenticateToken,
    (req: AuthenticatedRequest, res: Response) => {
        if (!req.user) {
            // return res.sendStatus(403); // 确保 req.user 存在
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


// 添加活动记录的接口
export const addActivity = (req: AuthenticatedRequest, res: Response) => {
    if (!req.user || (req.user.isAdmin !== 1 && req.user.isAdmin !== 2)) {
        // 如果用户不是管理员或教师，返回403禁止访问
        return res.status(403).json({ message: 'Forbidden' });
    }

    const { uid, activity_name, activity_location, activity_date, activity_description, hours, organizer_name, organizer_email, status, admin_comment } = req.body;

    if (!uid || !activity_name || !activity_date) {
        return res.status(400).json({ message: 'uid, activity_name, and activity_date are required.' });
    }

    pool.query(
        'INSERT INTO activities_data (uid, activity_name, activity_location, activity_date, activity_description, hours, organizer_name, organizer_email, status, admin_comment) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [uid, activity_name, activity_location, activity_date, activity_description, hours, organizer_name, organizer_email, status, admin_comment],
        (error, results) => {
            if (error) {
                return res.status(500).json({ message: 'Add activity failed', error });
            }
            res.status(201).json({ message: 'Activity added successfully' });
        }
    );
};

// 修改活动记录的接口
export const updateActivity = (req: AuthenticatedRequest, res: Response) => {
    if (!req.user) {
        return res.status(401).json({ message: '未授权' });
    }

    const { id, activityName, activityLocation, activityDate, activityDescription, hours, organizerName, organizerEmail, status, adminComment } = req.body;

    pool.query(
        'UPDATE activities_data SET activity_name = ?, activity_location = ?, activity_date = ?, activity_description = ?, hours = ?, organizer_name = ?, organizer_email = ?, status = ?, admin_comment = ? WHERE id = ? AND uid = ?',
        [activityName, activityLocation, activityDate, activityDescription, hours, organizerName, organizerEmail, status, adminComment, id, req.user.uid],
        (error, results) => {
            if (error) {
                return res.status(500).json({ message: '更新活动失败', error });
            }
            res.status(200).json({ message: '更新活动成功' });
        }
    );
};

// 获取活动记录的接口
export const getActivities = (req: Request, res: Response) => {
    const authHeader = req.headers['authorization'];
    let uid: string | undefined;

    if (authHeader) {
        const accessToken = authHeader.split(' ')[1];
        try {
            const decodedToken = verifyToken(accessToken, process.env.JWT_SECRET as string);
            uid = decodedToken.uid; // 使用 uid 而不是 id
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

    // 打印 uid 以便调试
    // console.log('UID:', uid);

    // 从数据库中获取活动记录
    pool.query('SELECT * FROM activities_data WHERE uid = ?', [uid], (error, results) => {
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

    pool.query(
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

// 审核活动的接口
export const reviewActivity = (req: AuthenticatedRequest, res: Response) => {
    if (!req.user || req.user.isAdmin !== 1) {
        // 如果用户不是管理员，返回403禁止访问
        return res.status(403).json({ message: 'Forbidden' });
    }

    const { id, status, admin_comment } = req.body;

    if (!id || !status) {
        return res.status(400).json({ message: 'id and status are required.' });
    }

    pool.query(
        'UPDATE activities_data SET status = ?, admin_comment = ? WHERE id = ?',
        [status, admin_comment, id],
        (error, results) => {
            if (error) {
                return res.status(500).json({ message: 'Review activity failed', error });
            }

            const resultHeader = results as ResultSetHeader;
            if (resultHeader.affectedRows === 0) {
                return res.status(404).json({ message: 'Activity not found' });
            }
            res.status(200).json({ message: 'Activity reviewed successfully' });
        }
    );
};
