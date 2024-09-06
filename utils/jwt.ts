import jwt from 'jsonwebtoken';

interface DecodedToken {
    id: string | number;
    isAdmin: number;
    uid: string;
}

/**
 * 生成 JWT token
 * @param userId 用户 ID，可以是 number 或者 string
 * @param uid 用户唯一识别号
 * @param secret JWT 秘钥
 * @param expiration 过期时间，例如 '15d'
 * @param isAdmin 是否为管理员
 * @returns 生成的 JWT token
 */
export const generateToken = (userId: number | string, uid: string, secret: string, expiration: string = '15d', isAdmin: number) => {
    const payload = { id: userId, uid, isAdmin }; // 包含 uid
    return jwt.sign(payload, secret, { expiresIn: expiration });
};

/**
 * 验证 JWT token
 * @param token JWT token 字符串
 * @param secret JWT 秘钥
 * @returns 验证结果，成功则返回解码后的 payload，否则抛出错误
 */
export const verifyToken = (token: string, secret: string) => {
    try {
        return jwt.verify(token, secret) as { id: number, uid: string, isAdmin: number };
    } catch (err) {
        throw new Error('Token verification failed.'); // 自定义错误处理
    }
};