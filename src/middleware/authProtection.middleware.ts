import { UserModel } from '@/models';
import { Request, Response, NextFunction } from 'express';
import jwt, { TokenExpiredError, JsonWebTokenError } from 'jsonwebtoken';

export const authProtection = async (req: Request, res: Response, next: NextFunction): Promise<any> => {
	try {
		const token = req.cookies.authToken || req.headers.authorization?.split(' ')[1];
		if (!token) return res.status(401).json({ error: 'Нет токена' });
		const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as any;
		const user = await UserModel.findById(decoded.userId);
		if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

		req.user = user;
		next();
	} catch (err: any) {
		if (err instanceof TokenExpiredError) {
			return res.status(401).json({ error: 'Срок действия токена истёк' });
		}
		if (err instanceof JsonWebTokenError) {
			return res.status(401).json({ error: 'Неверный токен' });
		}
		return res.status(401).json({ error: 'Ошибка токена' });
	}
};
