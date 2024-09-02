import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

export const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);

    try {
        const user = jwt.verify(token, process.env.JWT_SECRET!); 
        req['user'] = user;
        next();
    } catch (err) {
        return res.sendStatus(403); // Token is invalid or expired
    }
};