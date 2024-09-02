// src/types/express.d.ts
import * as express from 'express';

declare global {
    namespace Express {
        interface Request {
            user?: {
                id: string | number; // 这里的结构可以根据您的需求扩展
            };
        }
    }
}
