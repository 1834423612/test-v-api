import { Request, Response } from 'express';
import pool from '../config/db';
import { RowDataPacket, ResultSetHeader } from 'mysql2';
import { AuthenticatedRequest } from '../models/types';

// 获取所有活动
export const getActivities = (req: Request, res: Response) => {
    pool.query('SELECT * FROM activities', (error, activities: RowDataPacket[]) => {
        if (error) {
            return res.status(500).json({ error: '无法获取活动列表' });
        }

        pool.query('SELECT * FROM activity_dates', (error, activityDates: RowDataPacket[]) => {
            if (error) {
                return res.status(500).json({ error: '无法获取活动日期' });
            }

            const activitiesWithDates = activities.map((activity: any) => {
                const dates = activityDates.filter((date: any) => date.activity_id === activity.id);
                return { ...activity, dates };
            });

            res.json(activitiesWithDates);
        });
    });
};

// 获取单个活动
export const getActivity = (req: Request, res: Response) => {
    const { id } = req.params;
    pool.query('SELECT * FROM activities WHERE id = ?', [id], (error, activities: RowDataPacket[]) => {
        if (error) {
            return res.status(500).json({ error: '无法获取活动' });
        }

        if (activities.length === 0) {
            return res.status(404).json({ error: '活动未找到' });
        }

        pool.query('SELECT * FROM activity_dates WHERE activity_id = ?', [id], (error, activityDates: RowDataPacket[]) => {
            if (error) {
                return res.status(500).json({ error: '无法获取活动日期' });
            }

            const activity = { ...activities[0], dates: activityDates };
            res.json(activity);
        });
    });
};

// 创建新活动
export const createActivity = (req: AuthenticatedRequest, res: Response) => {
    if (!req.user || req.user.isAdmin !== 1) {
        return res.status(403).json({ message: '无权限' });
    }

    const { title, location, categories, posterUrl, organizer, organizerEmail, content, dates } = req.body;
    pool.query(
        'INSERT INTO activities (title, location, categories, posterUrl, organizer, organizerEmail, content) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [title, location, categories.join(','), posterUrl, organizer, organizerEmail, JSON.stringify(content)],
        (error, results: ResultSetHeader) => {
            if (error) {
                return res.status(500).json({ error: '无法创建活动' });
            }

            const activityId = results.insertId;
            dates.forEach((date: any) => {
                pool.query(
                    'INSERT INTO activity_dates (activity_id, date, duration, participants) VALUES (?, ?, ?, ?)',
                    [activityId, date.date, date.duration, date.participants],
                    (error) => {
                        if (error) {
                            return res.status(500).json({ error: '无法创建活动日期' });
                        }
                    }
                );
            });

            res.status(201).json({ message: '活动创建成功' });
        }
    );
};

// 更新活动
export const updateActivity = (req: AuthenticatedRequest, res: Response) => {
    if (!req.user || req.user.isAdmin !== 1) {
        return res.status(403).json({ message: '无权限' });
    }

    const { id } = req.params;
    let { title, location, categories, posterUrl, organizer, organizerEmail, content, dates } = req.body;

    // 检查 categories 是否为字符串，如果是则转换为数组
    if (typeof categories === 'string') {
        categories = categories.split(',');
    }

    pool.query(
        'UPDATE activities SET title = ?, location = ?, categories = ?, posterUrl = ?, organizer = ?, organizerEmail = ?, content = ? WHERE id = ?',
        [title, location, categories.join(','), posterUrl, organizer, organizerEmail, JSON.stringify(content), id],
        (error) => {
            if (error) {
                return res.status(500).json({ error: '无法更新活动' });
            }

            pool.query('DELETE FROM activity_dates WHERE activity_id = ?', [id], (error) => {
                if (error) {
                    return res.status(500).json({ error: '无法删除旧的活动日期' });
                }

                dates.forEach((date: any) => {
                    pool.query(
                        'INSERT INTO activity_dates (activity_id, date, duration, participants) VALUES (?, ?, ?, ?)',
                        [id, date.date, date.duration, date.participants],
                        (error) => {
                            if (error) {
                                return res.status(500).json({ error: '无法更新活动日期' });
                            }
                        }
                    );
                });

                res.json({ message: '活动更新成功' });
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
    pool.query('UPDATE activities SET is_deleted = 1, deleted_at = NOW() WHERE id = ?', [id], (error) => {
        if (error) {
            return res.status(500).json({ error: '无法删除活动' });
        }

        res.json({ message: '活动删除成功' });
    });
};
