import jwt from 'jsonwebtoken';

export const generateToken = (userId: number | string, secret: string, expiration: string) => {
    return jwt.sign({ id: userId }, secret, { expiresIn: expiration });
};

export const verifyToken = (token: string, secret: string) => {
    return jwt.verify(token, secret);
};