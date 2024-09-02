import { Request, Response, NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';

interface AuthenticatedRequest extends Request {
    user?: {
        id: string | number;
    };
}

export const authenticateToken = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401); // 如果没有token，返回401

    jwt.verify(token, process.env.JWT_SECRET!, (err, decoded) => {
        if (err) return res.sendStatus(403); // 如果token无效，返回403

        if (decoded) {
            // 确保 decoded 符合预期结构，这里假设 decoded 包含一个 id 字段
            req.user = decoded ? {
                id: (decoded as { id: string | number }).id
            } : undefined;
        } else {
            req.user = undefined; // 设置为undefined以避免在后续处理中出现问题
        }

        next(); // 下一步 middleware
    });
};
