import { Request } from 'express';

export interface AuthenticatedRequest extends Request {
    user?: {
        id: string | number;
        isAdmin: number;
        uid: string;
    };
}
