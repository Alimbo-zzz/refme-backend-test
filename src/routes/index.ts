import { Router } from 'express';
import authRoutes from './auth.route';
import testRoutes from './test.route';
import profileRoutes from './profile.route';

const router = Router();

router.use('/auth', authRoutes);
router.use('/profile', profileRoutes);
router.use('/test', testRoutes);

export default router;