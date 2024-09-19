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
    pool.query('SELECT * FROM users WHERE uid = ?', [req.user.uid], (error, results) => {
        if (error) {
            return res.status(500).json({ message: '获取用户信息失败', error });
        }

        const queryResults = results as any[];
        if (queryResults.length === 0) {
            return res.status(404).json({ message: '用户不存在' });
        }

        const user = queryResults[0] as UserInfo;
        return res.status(200).json(user);
    });
};