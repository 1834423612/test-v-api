import { Router } from 'express';
import { authenticateToken } from '../middlewares/authMiddleware';
import {
    register,
    login,
    refreshToken,
    getUserInfo,
    setAdmin,
    getActivities,
    addActivity,
    updateActivity,
    deleteActivity
} from '../controllers/authController';

const router = Router();

// 用户注册
router.post('/register', register);

// 用户登录
router.post('/login', login);

// 刷新 Token 的路由，使用中间件进行身份验证
router.post('/refresh-token', authenticateToken, refreshToken);

// 获取当前登录用户信息的路由，使用中间件进行身份验证
router.get('/userinfo', authenticateToken, getUserInfo);

// 设置用户权限的路由，使用中间件进行身份验证
router.post('/set-admin', authenticateToken, setAdmin);

// 获取活动记录的路由，使用中间件进行身份验证
router.get('/activities', getActivities);

// 添加活动的路由，使用中间件进行身份验证
router.post('/activities/add', authenticateToken, addActivity);

// 修改活动的路由，使用中间件进行身份验证
router.put('/activities/update', authenticateToken, updateActivity);

// 删除活动的路由，使用中间件进行身份验证
router.delete('/activities/delete', authenticateToken, deleteActivity);

export default router;
