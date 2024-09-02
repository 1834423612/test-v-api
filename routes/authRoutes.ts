import { Router } from 'express';
import { register, login, refreshToken } from '../controllers/authController';
import { authenticateToken } from '../middlewares/authMiddleware';

const router = Router();

// 用户注册
router.post('/register', register);

// 用户登录
router.post('/login', login);

// 刷新 Token 的路由，使用中间件进行身份验证
router.post('/refresh-token', authenticateToken, refreshToken);

export default router;
