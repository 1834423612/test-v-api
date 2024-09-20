import { Request } from 'express';

export interface AuthenticatedRequest extends Request {
    user?: {
        id: string | number;
        isAdmin: number;
        uid: string;
    };
}

// 定义用户信息的接口
export interface UserInfo {
    id: number;
    username: string;
    uid: string;
    first_name: string;
    last_name: string;
    graduation_year: number;
    isAdmin: number;
    interior_email: string;
    exterior_email: string;
    latest_ip: string;
    updated_at: string;
    created_at: string;
}