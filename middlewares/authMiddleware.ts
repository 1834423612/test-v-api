// middlewares/authMiddleware.ts
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { AuthenticatedRequest } from '../models/types';

interface DecodedToken {
    id: string | number;
    isAdmin: number;
    uid: string;
}

export const authenticateToken = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401); // 如果没有提供 Token，返回 401 未授权

    jwt.verify(token, process.env.JWT_SECRET as string, (err, decodedToken) => {
        if (err) {
            console.error('Token verification error:', err);
            return res.sendStatus(403); // 如果 Token 无效，返回 403 禁止访问
        }
        
        // 确保 decodedToken 为对象并包含 id
        if (typeof decodedToken === 'object' && decodedToken !== null) {
            req.user = {
                id: decodedToken.id,       // id 从 JWT 中获取
                isAdmin: decodedToken.isAdmin,
                uid: decodedToken.id       // 这里使用 id 映射为 uid
            };
        } else {
            console.warn('Decoded token is not in the expected format.');
        }

        next();
    });
}
