import { Request, Response } from 'express';
import pool from '../config/db';
import { RowDataPacket, ResultSetHeader } from 'mysql2';
import { AuthenticatedRequest } from '../models/types';
import sharp from 'sharp';

// 压缩和优化 base64 编码的图片
const optimizeBase64Image = async (base64Data: string): Promise<string> => {
    const buffer = Buffer.from(base64Data, 'base64');
    const optimizedBuffer = await sharp(buffer)
        // .resize(800) // 调整图片大小，宽度为800px
        .png({ quality: 80 }) // 转换为png格式，并设置质量为80
        .toBuffer();
    return optimizedBuffer.toString('base64');
};

// 获取所有活动
export const getActivities = (req: Request, res: Response) => {
    pool.query('SELECT * FROM activity_posts WHERE is_deleted = 0', (error, activities: RowDataPacket[]) => {
        if (error) {
            return res.status(500).json({ error: '无法获取活动列表' });
        }

        pool.query('SELECT * FROM activity_posts_dates', (error, activityDates: RowDataPacket[]) => {
            if (error) {
                return res.status(500).json({ error: '无法获取活动日期' });
            }

            const activitiesWithDates = activities.map((activity: any) => {
                const dates = activityDates.filter((date: any) => date.activity_id === activity.id);
                return { 
                    id: activity.id,
                    uid: activity.uid,
                    activity_name: activity.activity_name,
                    activity_location: activity.activity_location,
                    activity_description: JSON.parse(activity.activity_description).ops.map((op: any) => op.insert).join(''),
                    categories: activity.categories,
                    posterUrl: activity.posterUrl,
                    organizer_name: activity.organizer_name,
                    organizer_email: activity.organizer_email,
                    status: activity.status,
                    shift: dates
                };
            });

            res.json(activitiesWithDates);
        });
    });
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

            const activity = { 
                id: activities[0].id,
                uid: activities[0].uid,
                activity_name: activities[0].activity_name,
                activity_location: activities[0].activity_location,
                activity_description: JSON.parse(activities[0].activity_description).ops.map((op: any) => op.insert).join(''),
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
        const base64Data = posterUrl.replace(/^data:image\/\w+;base64,/, '');
        optimizedPosterUrl = await optimizeBase64Image(base64Data);
    }

    try {
        const [results] = await pool.promise().query(
            'INSERT INTO activity_posts (uid, activity_name, activity_location, activity_description, organizer_name, organizer_email, categories, posterUrl) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [req.user.uid, activity_name, activity_location, JSON.stringify(activity_description), organizer_name, organizer_email, JSON.stringify(categories), optimizedPosterUrl]
        );

        const activityId = (results as any).insertId;

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
    let { title, location, activity_description, organizer, organizerEmail, dates, categories, posterUrl } = req.body;

    if (!title || !dates || !location || !categories || !organizer || !organizerEmail || !activity_description) {
        return res.status(400).json({ message: '必填字段不能为空' });
    }

    let optimizedPosterUrl = null;
    if (posterUrl) {
        const base64Data = posterUrl.replace(/^data:image\/\w+;base64,/, '');
        optimizedPosterUrl = await optimizeBase64Image(base64Data);
    }

    pool.query(
        'UPDATE activity_posts SET activity_name = ?, activity_location = ?, activity_description = ?, organizer_name = ?, organizer_email = ?, categories = ?, posterUrl = ? WHERE id = ?',
        [title, location, JSON.stringify(activity_description), organizer, organizerEmail, JSON.stringify(categories), optimizedPosterUrl, id],
        (error) => {
            if (error) {
                return res.status(500).json({ error: '无法更新活动' });
            }

            pool.query('DELETE FROM activity_posts_dates WHERE activity_id = ?', [id], (error) => {
                if (error) {
                    return res.status(500).json({ error: '无法删除旧的活动日期' });
                }

                const shiftValues = dates.map((s: any) => [id, s.date, s.duration, s.participants]);
                pool.query(
                    'INSERT INTO activity_posts_dates (activity_id, date, duration, participants) VALUES ?',
                    [shiftValues],
                    (error) => {
                        if (error) {
                            return res.status(500).json({ error: '无法更新活动日期' });
                        }

                        // 计算总的参与人数和总的小时数
                        const activity_participate_num = dates.reduce((total: number, s: any) => total + (s.participants || 0), 0);
                        const hours = dates.reduce((total: number, s: any) => total + (s.duration || 0), 0);

                        res.json({ message: '活动更新成功', activity_participate_num, hours, shift: shiftValues });
                    }
                );
            });
        }
    );
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
