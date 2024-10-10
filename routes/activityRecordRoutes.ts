import { Router } from 'express';
import { authenticateToken } from '../middlewares/authMiddleware';
import { getActivityRecord, addActivityRecord, updateActivityRecord, deleteActivityRecord, reviewActivityRecord } from '../controllers/activityRecordController';

const router = Router();

router.get('/', getActivityRecord);
router.post('/add', authenticateToken, addActivityRecord);
router.put('/update/:id', authenticateToken, updateActivityRecord);
router.delete('/delete/:id', authenticateToken, deleteActivityRecord);
router.put('/review/:id', authenticateToken, reviewActivityRecord);

export default router;