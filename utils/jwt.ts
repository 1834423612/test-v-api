import jwt from 'jsonwebtoken';

/**
 * 生成 JWT token
 * @param userId 用户 ID，可以是 number 或者 string
 * @param secret JWT 秘钥
 * @param expiration 过期时间，例如 '15d'
 * @returns 生成的 JWT token
 */
export const generateToken = (userId: number | string, secret: string, expiration: string = '15d') => {
    const payload = { id: userId }; // 可以在这里添加其他用户数据
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
        return jwt.verify(token, secret) as any; // 强制转换为 any 类型以获取 payload
    } catch (err) {
        throw new Error('Token verification failed.'); // 自定义错误处理
    }
};
