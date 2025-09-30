import { generateCode, generateTokens, sendEmail } from '@/utils';
import { Router } from 'express';

const router = Router();

router.get('/', (_req, res) => {
	const token = generateTokens('user-id-test');
	res.status(200).json({ status: 'ok' });
});

router.get('/get-env', (_req, res) => {
	const {
		PORT,
		SMTP_HOST,
		SMTP_PORT,
		SMTP_SECURE,
		SMTP_USER,
		SMTP_PASS,
	} = process.env;


	const data = {
		PORT,
		SMTP_HOST,
		SMTP_PORT,
		SMTP_SECURE,
		SMTP_USER,
		SMTP_PASS,
	}

	res.status(200).json({ status: 'ok', data });
});


router.get('/send-mail', (_req: any, res: any) => {
	try {
		const { mail = 'alimbo.test.2@gmail.com' } = _req.query;
		const code = generateCode(4);
		sendEmail(mail, { subject: 'RefMe verify code', text: `Your verification code is: ${code}` });

		return res.status(200).json({ message: 'Verification code resent' });
	} catch (err) {
		console.error(err);
		return res.status(500).json({ message: 'Internal server error' });
	}
});

export default router;
