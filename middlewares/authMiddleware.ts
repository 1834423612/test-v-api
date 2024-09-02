import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { AuthenticatedRequest } from '../models/types'; 
import connection from '../config/db';

export const authenticateToken = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401); // 如果没有提供 Token，返回 401 未授权

    jwt.verify(token, process.env.JWT_SECRET as string, (err, decodedToken) => {
        if (err) return res.sendStatus(403); // 如果 Token 无效，返回 403 禁止访问

        // 手动设置 req.user 的属性
        req.user = {
            id: (decodedToken as any).id,
            isAdmin: (decodedToken as any).isAdmin,
            uid: (decodedToken as any).uid
        };

        next();
    });
};
