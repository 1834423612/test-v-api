import { Request, Response } from 'express';
import { User } from '../models/User';
import pool from '../config/db';
import { AuthenticatedRequest, UserInfo } from '../models/types';
import { generateToken, verifyToken } from '../utils/jwt';
import jwt from 'jsonwebtoken';

// 设置管理员接口
export const setAdmin = (req: AuthenticatedRequest, res: Response) => {
    if (!req.user) {
        return res.sendStatus(403);
    }

    const { userId, isAdmin } = req.body;

    // 检查当前用户是否为管理员
    pool.query('SELECT isAdmin FROM users WHERE uid = ?', [req.user.id], (error, results) => {
        if (error) {
            return res.status(500).json({ message: '设置管理员失败', error });
        }

        const selectResults = results as any[];
        if (selectResults.length === 0 || selectResults[0].isAdmin !== 1) {
            return res.sendStatus(403);
        }

        pool.query('UPDATE users SET isAdmin = ? WHERE id = ?', [isAdmin, userId], (error, results) => {
            if (error) {
                return res.status(500).json({ message: '设置管理员失败', error });
            }
            return res.status(200).json({ message: '设置管理员成功' });
        });
    });
};

// 获取当前登录用户信息的接口
export const getUserInfo = (req: AuthenticatedRequest, res: Response) => {
    if (!req.user) {
        return res.sendStatus(403);
    }

    const userId = req.user.id;

    // 从数据库中获取用户信息
    pool.query('SELECT * FROM users WHERE uid = ? AND is_deleted = 0', [req.user.uid], (error, results) => {
        if (error) {
            return res.status(500).json({ message: '获取用户信息失败', error });
        }

        const queryResults = results as any[];
        if (queryResults.length === 0) {
            return res.status(404).json({ message: '用户不存在' });
        }

        const user = queryResults[0] as UserInfo;
        const filteredUser = {
            id: user.id,
            username: user.username,
            uid: user.uid,
            first_name: user.first_name,
            last_name: user.last_name,
            graduation_year: user.graduation_year,
            interior_email: user.interior_email,
            exterior_email: user.exterior_email,
            isAdmin: user.isAdmin,
            latest_ip: user.latest_ip,
        };
        return res.status(200).json(filteredUser);
    });
};

// 获取所有用户信息的接口
export const getAllUsersInfo = (req: AuthenticatedRequest, res: Response) => {
    if (!req.user) {
        return res.sendStatus(403);
    }

    // 检查当前用户是否为管理员
    if (req.user.isAdmin !== 1 && req.user.isAdmin !== 2) {
        return res.sendStatus(403);
    }

    // 从数据库中获取所有用户信息
    pool.query('SELECT * FROM users WHERE is_deleted = 0', (error, results) => {
        if (error) {
            return res.status(500).json({ message: '获取所有用户信息失败', error });
        }

        const users = results as UserInfo[];
        const filteredUsers = users.map(user => ({
            id: user.id,
            username: user.username,
            uid: user.uid,
            first_name: user.first_name,
            last_name: user.last_name,
            graduation_year: user.graduation_year,
            interior_email: user.interior_email,
            exterior_email: user.exterior_email,
            isAdmin: user.isAdmin,
            latest_ip: user.latest_ip,
            updated_at: user.updated_at,
            created_at: user.created_at,
        }));
        return res.status(200).json(filteredUsers);
    });
};

// 添加新用户的接口
export const addUser = (req: AuthenticatedRequest, res: Response) => {
    const { username, uid, first_name, last_name, graduation_year, interior_email, exterior_email, isAdmin } = req.body;

    pool.query(
        'INSERT INTO users (username, uid, first_name, last_name, graduation_year, interior_email, exterior_email, isAdmin) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [username, uid, first_name, last_name, graduation_year, interior_email, exterior_email, isAdmin],
        (error, results) => {
            if (error) {
                return res.status(500).json({ message: '添加用户失败', error });
            }
            return res.status(201).json({ message: '添加用户成功' });
        }
    );
};

// 更新用户信息的接口
export const updateUser = (req: AuthenticatedRequest, res: Response) => {
    const { id } = req.params;
    const { username, uid, first_name, last_name, graduation_year, interior_email, exterior_email, isAdmin } = req.body;

    pool.query(
        'UPDATE users SET username = ?, uid = ?, first_name = ?, last_name = ?, graduation_year = ?, interior_email = ?, exterior_email = ?, isAdmin = ? WHERE id = ?',
        [username, uid, first_name, last_name, graduation_year, interior_email, exterior_email, isAdmin, id],
        (error, results) => {
            if (error) {
                return res.status(500).json({ message: '更新用户信息失败', error });
            }
            return res.status(200).json({ message: '更新用户信息成功' });
        }
    );
};

// 删除单个用户的接口（逻辑删除）
export const deleteUser = (req: AuthenticatedRequest, res: Response) => {
    const { id } = req.params;

    pool.query('UPDATE users SET is_deleted = 1, deleted_at = NOW() WHERE id = ?', [id], (error, results) => {
        if (error) {
            return res.status(500).json({ message: '删除用户失败', error });
        }
        return res.status(200).json({ message: '删除用户成功' });
    });
};

// 批量删除用户的接口（逻辑删除）
export const batchDeleteUsers = (req: AuthenticatedRequest, res: Response) => {
    const { ids } = req.body;

    pool.query('UPDATE users SET is_deleted = 1, deleted_at = NOW() WHERE id IN (?)', [ids], (error, results) => {
        if (error) {
            return res.status(500).json({ message: '批量删除用户失败', error });
        }
        return res.status(200).json({ message: '批量删除用户成功' });
    });
};