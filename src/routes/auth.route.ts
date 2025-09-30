import { Router } from 'express';
import { authApple, authGoogle, callbackApple, callbackGoogle, login, logout, refreshToken, register, resendVerifyCode, verifyCode } from '@/controllers';

const router = Router();


router.post('/login', login);
router.post('/register', register);
router.get('/logout', logout);
router.get('/refresh', refreshToken);

router.post('/resend-verify-code', resendVerifyCode);
router.post('/verify-code', verifyCode);

router.get('/google', authGoogle);
router.get('/google/callback', callbackGoogle);

router.get('/apple', authApple);
router.get('/apple/callback', callbackApple);


export default router;
