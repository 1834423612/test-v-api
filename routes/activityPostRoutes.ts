import { Router } from 'express';
import { getActivities, getActivity, createActivity, updateActivity, deleteActivity } from '../controllers/activityPostController';
import { authenticateToken } from '../middlewares/authMiddleware';

const router = Router();

router.get('/', getActivities);
router.get('/:id', getActivity);
router.post('/create', authenticateToken, createActivity);
router.put('/update/:id', authenticateToken, updateActivity);
router.delete('/delete/:id', authenticateToken, deleteActivity);

export default router;
