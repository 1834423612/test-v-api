import { Request, Response } from 'express';
import pool from '../config/db';
import { AuthenticatedRequest } from '../models/types';
import { verifyToken } from '../utils/jwt';
import { ResultSetHeader, RowDataPacket } from 'mysql2';

// 获取活动记录的接口
export const getActivityRecord = (req: Request, res: Response) => {
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
            return res.status(400).json({ message: '缺少必要的查询参数' });
        }

        // 验证查询参数中的 uid、first_name 和 last_name 是否匹配
        pool.query('SELECT * FROM users WHERE uid = ? AND first_name = ? AND last_name = ?', [uid, firstName, lastName], (error, results: RowDataPacket[]) => {
            if (error) {
                console.error('Database query error:', error);
                return res.status(500).json({ error: '验证用户信息失败' });
            }

            if (results.length === 0) {
                return res.status(404).json({ error: '用户信息不匹配' });
            }

            // 查询匹配用户的活动数据
            pool.query('SELECT * FROM activity_record_data WHERE uid = ? AND is_deleted = 0', [uid], (error, results) => {
                if (error) {
                    console.error('Database query error:', error);
                    return res.status(500).json({ error: '获取活动数据失败' });
                }
                res.status(200).json(results);
            });
        });
        return;
    }

    // 检查当前用户是否为管理员
    pool.query('SELECT isAdmin FROM users WHERE uid = ?', [uid], (error, results: RowDataPacket[]) => {
        if (error) {
            console.error('Database query error:', error);
            return res.status(500).json({ error: '检查用户权限失败' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: '用户未找到' });
        }

        const isAdmin = results[0].isAdmin;
        const all = req.query.all === 'true';

        // 如果用户是管理员且查询参数 all=true，查询所有用户的数据；否则，只查询当前用户的数据
        const query = isAdmin && all
            ? 'SELECT * FROM activity_record_data WHERE is_deleted = 0'
            : 'SELECT * FROM activity_record_data WHERE uid = ? AND is_deleted = 0';
        const queryParams = isAdmin && all ? [] : [uid];

        pool.query(query, queryParams, (error, results) => {
            if (error) {
                console.error('Database query error:', error);
                return res.status(500).json({ error: '获取活动数据失败' });
            }
            res.status(200).json(results);
        });
    });
};

// 添加提交记录的接口
export const addActivityRecord = (req: AuthenticatedRequest, res: Response) => {
    if (!req.user || (req.user.isAdmin !== 1 && req.user.isAdmin !== 2)) {
        // 如果用户不是管理员或教师，返回403禁止访问
        return res.status(403).json({ message: 'Forbidden' });
    }

    const { uid, activity_name, activity_location, activity_date, activity_description, hours, organizer_name, organizer_email, status, admin_comment } = req.body;

    if (!uid || !activity_name || !activity_date) {
        return res.status(400).json({ message: 'uid, activity_name, and activity_date are required.' });
    }

    pool.query(
        'INSERT INTO submission (uid, activity_name, activity_location, activity_date, activity_description, hours, organizer_name, organizer_email, status, admin_comment, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())',
        [uid, activity_name, activity_location, activity_date, activity_description, hours, organizer_name, organizer_email, status, admin_comment],
        (error, results) => {
            if (error) {
                return res.status(500).json({ message: 'Add submission record failed', error });
            }
            res.status(201).json({ message: 'Submission record added successfully', submissionId: (results as ResultSetHeader).insertId });
        }
    );
};

// 修改活动记录的接口
export const updateActivityRecord = (req: AuthenticatedRequest, res: Response) => {
    if (!req.user) {
        return res.status(401).json({ message: '未授权' });
    }

    const { id, uid, activity_name, activity_location, activity_date, activity_description, hours, organizer_name, organizer_email, status, admin_comment } = req.body;

    // 检查必填字段是否为 null 或 undefined
    if (!id || !uid || !activity_name || !activity_location || !activity_date || !hours || !organizer_name || !status) {
        return res.status(400).json({ message: '必填字段不能为空' });
    }

    pool.query(
        'UPDATE activity_record_data SET activity_name = ?, activity_location = ?, activity_date = ?, activity_description = ?, hours = ?, organizer_name = ?, organizer_email = ?, status = ?, admin_comment = ?, updated_at = NOW() WHERE id = ? AND uid = ?',
        [activity_name, activity_location, activity_date, activity_description, hours, organizer_name, organizer_email, status, admin_comment, id, uid],
        (error, results) => {
            if (error) {
                return res.status(500).json({ message: '更新活动失败', error });
            }
            res.status(200).json({ message: '更新活动成功' });
        }
    );
};

// 删除活动记录的接口（物理删除）
// export const deleteActivity = (req: AuthenticatedRequest, res: Response) => {
//     if (!req.user || req.user.isAdmin !== 1) {
//         return res.sendStatus(403); // 如果用户不是管理员，返回403禁止访问
//     }

//     const { id } = req.body;

//     pool.query(
//         'DELETE FROM activities_data WHERE id = ?',
//         [id],
//         (error, results) => {
//             if (error) {
//                 console.error('Database delete error:', error);
//                 return res.status(500).json({ error: 'Failed to delete activity.' });
//             }

//             res.status(200).json({ message: 'Activity deleted successfully.' });
//         }
//     );
// };

// 删除活动记录的接口（逻辑删除）
export const deleteActivityRecord = (req: AuthenticatedRequest, res: Response) => {
    if (!req.user || req.user.isAdmin !== 1) {
        return res.sendStatus(403); // 如果用户不是管理员，返回403禁止访问
    }

    const { id } = req.body;

    pool.query(
        'UPDATE activity_record_data SET is_deleted = 1, deleted_at = NOW() WHERE id = ?',
        [id],
        (error, results) => {
            if (error) {
                console.error('Database update error:', error);
                return res.status(500).json({ error: 'Failed to delete submission record.' });
            }

            res.status(200).json({ message: 'Submission record deleted successfully.' });
        }
    );
};

// 审核活动的接口
export const reviewActivityRecord = (req: AuthenticatedRequest, res: Response) => {
    if (!req.user || req.user.isAdmin !== 1) {
        // 如果用户不是管理员，返回403禁止访问
        return res.status(403).json({ message: 'Forbidden' });
    }

    const { id, status, admin_comment } = req.body;

    if (!id || !status) {
        return res.status(400).json({ message: 'id and status are required.' });
    }

    pool.query(
        'UPDATE activity_record_data SET status = ?, admin_comment = ?, updated_at = NOW() WHERE id = ?',
        [status, admin_comment, id],
        (error, results) => {
            if (error) {
                return res.status(500).json({ message: 'Review submission record failed', error });
            }

            const resultHeader = results as ResultSetHeader;
            if (resultHeader.affectedRows === 0) {
                return res.status(404).json({ message: 'Submission record not found' });
            }
            res.status(200).json({ message: 'Submission record reviewed successfully' });
        }
    );
};
