import * as express from 'express';

declare global {
    namespace Express {
        interface Request {
            user?: any; // This can be replaced with a more specific type, such as { id: string, username: string }
        }
    }
}
