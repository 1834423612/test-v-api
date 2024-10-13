import { Request, Response } from 'express';
import pool from '../config/db';
import { RowDataPacket, ResultSetHeader } from 'mysql2';
import { AuthenticatedRequest } from '../models/types';
import sharp from 'sharp';

// 压缩和优化 base64 编码的图片
const optimizeBase64Image = async (base64Data: string, mimeType: string): Promise<string> => {
    const buffer = Buffer.from(base64Data, 'base64');
    const optimizedBuffer = await sharp(buffer)
        .png({ quality: 80 })        .toBuffer();
    return `data:${mimeType};base64,${optimizedBuffer.toString('base64')}`;
};

// 获取所有活动
export const getActivities = async (req: Request, res: Response) => {
    try {
        const [activities] = await pool.promise().query('SELECT * FROM activity_posts WHERE is_deleted = 0') as RowDataPacket[][];

        if (!Array.isArray(activities) || activities.length === 0) {
            return res.status(404).json({ message: '没有找到活动' });
        }

        // 获取活动日期
        const [activityDates] = await pool.promise().query('SELECT * FROM activity_posts_dates') as RowDataPacket[][];

        if (!Array.isArray(activityDates)) {
            return res.status(404).json({ message: '没有找到活动日期' });
        }

        // 使用 for 循环代替 map
        const activitiesWithDates = [];
        for (const activity of activities) {
            const dates = activityDates.filter((date: any) => date.activity_id === activity.id);
            let activityDescription = '';
            if (activity.activity_description) {
                try {
                    const parsedDescription = JSON.parse(activity.activity_description);
                    if (parsedDescription.ops && Array.isArray(parsedDescription.ops)) {
                        activityDescription = parsedDescription.ops.map((op: any) => op.insert).join('');
                    } else {
                        activityDescription = activity.activity_description; // 如果不是预期的格式，直接使用原始字符串
                    }
                } catch (error) {
                    console.error('解析活动描述失败:', error);
                    activityDescription = activity.activity_description; // 如果解析失败，直接使用原始字符串
                }
            }
            activitiesWithDates.push({ 
                id: activity.id,
                uid: activity.uid,
                activity_name: activity.activity_name,
                activity_location: activity.activity_location,
                activity_description: activityDescription,
                categories: activity.categories,
                posterUrl: activity.posterUrl,
                organizer_name: activity.organizer_name,
                organizer_email: activity.organizer_email,
                status: activity.status,
                shift: dates
            });
        }

        res.json(activitiesWithDates);
    } catch (error) {
        console.error('获取活动失败:', error); // 打印错误以便调试
        res.status(500).json({ error: '无法获取活动列表' });
    }
};

// 获取单个活动
export const getActivity = (req: Request, res: Response) => {
    const { id } = req.params;
    pool.query('SELECT * FROM activity_posts WHERE id = ? AND is_deleted = 0', [id], (error, activities: RowDataPacket[]) => {
        if (error) {
            return res.status(500).json({ error: '无法获取活动' });
        }

        if (activities.length === 0) {
            return res.status(404).json({ error: '活动未找到' });
        }

        pool.query('SELECT * FROM activity_posts_dates WHERE activity_id = ?', [id], (error, activityDates: RowDataPacket[]) => {
            if (error) {
                return res.status(500).json({ error: '无法获取活动日期' });
            }

            let activityDescription = '';
            if (activities[0].activity_description) {
                try {
                    const parsedDescription = JSON.parse(activities[0].activity_description);
                    if (parsedDescription.ops && Array.isArray(parsedDescription.ops)) {
                        activityDescription = parsedDescription.ops.map((op: any) => op.insert).join('');
                    } else {
                        activityDescription = activities[0].activity_description; // 如果不是预期的格式，直接使用原始字符串
                    }
                } catch (error) {
                    console.error('解析活动描述失败:', error);
                    activityDescription = activities[0].activity_description; // 如果解析失败，直接使用原始字符串
                }
            }

            const activity = { 
                id: activities[0].id,
                uid: activities[0].uid,
                activity_name: activities[0].activity_name,
                activity_location: activities[0].activity_location,
                activity_description: activityDescription,
                categories: activities[0].categories,
                posterUrl: activities[0].posterUrl,
                organizer_name: activities[0].organizer_name,
                organizer_email: activities[0].organizer_email,
                status: activities[0].status,
                shift: activityDates
            };
            res.json(activity);
        });
    });
};

// 创建新活动
export const createActivity = async (req: AuthenticatedRequest, res: Response) => {
    if (!req.user || req.user.isAdmin !== 1) {
        return res.status(403).json({ message: '无权限' });
    }

    const { activity_name, shift, activity_location, categories, posterUrl, organizer_name, organizer_email, activity_description } = req.body;

    if (!activity_name || !shift || !activity_location || !categories || !organizer_name || !organizer_email || !activity_description) {
        return res.status(400).json({ message: '必填字段不能为空' });
    }

    let optimizedPosterUrl = null;
    if (posterUrl) {
        const matches = posterUrl.match(/^data:(image\/\w+);base64,(.*)$/);
        if (matches) {
            const mimeType = matches[1];
            const base64Data = matches[2];
            optimizedPosterUrl = await optimizeBase64Image(base64Data, mimeType);
        }
    }

    try {
        const [results] = await pool.promise().query(
            'INSERT INTO activity_posts (uid, activity_name, activity_location, activity_description, organizer_name, organizer_email, categories, posterUrl) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [req.user.uid, activity_name, activity_location, JSON.stringify({ ops: [{ insert: activity_description }] }), organizer_name, organizer_email, JSON.stringify(categories), optimizedPosterUrl]
        ) as unknown as [ResultSetHeader, RowDataPacket[]];

        const activityId = results.insertId;

        const shiftValues = shift.map((s: any) => [activityId, s.date, s.duration, s.participants]);
        await pool.promise().query(
            'INSERT INTO activity_posts_dates (activity_id, date, duration, participants) VALUES ?',
            [shiftValues]
        );

        // 计算总的参与人数和总的小时数
        const activity_participate_num = shift.reduce((total: number, s: any) => total + (s.participants || 0), 0);
        const hours = shift.reduce((total: number, s: any) => total + (s.duration || 0), 0);

        res.status(201).json({ message: '活动创建成功', activityId, activity_participate_num, hours, shift: shiftValues });
    } catch (error) {
        console.error('创建活动失败:', error);
        res.status(500).json({ message: '创建活动失败', error });
    }
};

// 更新活动
export const updateActivity = async (req: AuthenticatedRequest, res: Response) => {
    if (!req.user || req.user.isAdmin !== 1) {
        return res.status(403).json({ message: '无权限' });
    }

    const { id } = req.params;
    const { activity_name, activity_location, activity_description, organizer_name, organizer_email, shift, categories, posterUrl } = req.body;

    if (!activity_name || !shift || !activity_location || !categories || !organizer_name || !organizer_email || !activity_description) {
        return res.status(400).json({ message: '必填字段不能为空' });
    }

    let optimizedPosterUrl = null;
    if (posterUrl) {
        const matches = posterUrl.match(/^data:(image\/\w+);base64,(.*)$/);
        if (matches) {
            const mimeType = matches[1];
            const base64Data = matches[2];
            optimizedPosterUrl = await optimizeBase64Image(base64Data, mimeType);
        }
    }

    try {
        await pool.promise().query(
            'UPDATE activity_posts SET activity_name = ?, activity_location = ?, activity_description = ?, organizer_name = ?, organizer_email = ?, categories = ?, posterUrl = ? WHERE id = ?',
            [activity_name, activity_location, JSON.stringify({ ops: [{ insert: activity_description }] }), organizer_name, organizer_email, JSON.stringify(categories), optimizedPosterUrl, id]
        );

        await pool.promise().query('DELETE FROM activity_posts_dates WHERE activity_id = ?', [id]);

        const shiftValues = shift.map((s: any) => [id, s.date, s.duration, s.participants]);
        await pool.promise().query(
            'INSERT INTO activity_posts_dates (activity_id, date, duration, participants) VALUES ?',
            [shiftValues]
        );

        // 计算总的参与人数和总的小时数
        const activity_participate_num = shift.reduce((total: number, s: any) => total + (s.participants || 0), 0);
        const hours = shift.reduce((total: number, s: any) => total + (s.duration || 0), 0);

        res.json({ message: '活动更新成功', activity_participate_num, hours, shift: shiftValues });
    } catch (error) {
        console.error('更新活动失败:', error);
        res.status(500).json({ message: '更新活动失败', error });
    }
};

// 删除活动（逻辑删除）
export const deleteActivity = (req: AuthenticatedRequest, res: Response) => {
    if (!req.user || req.user.isAdmin !== 1) {
        return res.status(403).json({ message: '无权限' });
    }

    const { id } = req.params;
    pool.query('UPDATE activity_posts SET is_deleted = 1, deleted_at = NOW() WHERE id = ?', [id], (error) => {
        if (error) {
            return res.status(500).json({ error: '无法删除活动' });
        }

        res.json({ message: '活动删除成功' });
    });
};
