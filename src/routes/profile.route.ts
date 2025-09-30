import { Router } from 'express';
import { profileData, profileDelete } from '@/controllers';
import { authProtection } from '@/middleware';

const router = Router();


router.get('/data', authProtection, profileData);
router.delete('/delete', authProtection, profileDelete);

export default router;
