
import { Request, Response } from 'express';
import { UserModel } from '@/models/user.model';

export const profileData = async (req: Request, res: Response): Promise<any> => {
	try {
		const userId = req.user?._id;
		if (!userId) return res.status(401).json({ message: 'Unauthorized' });
		const user = await UserModel.findById(userId).select('-password -__v -createdAt -updatedAt');
		if (!user) return res.status(404).json({ message: 'User not found' });

		const userResponse = {
			id: (user._id as any).toString(),
			...user.toObject(), // если user — это документ Mongoose
		};

		delete userResponse._id;

		res.json(userResponse);
	} catch (error) {
		res.status(500).json({ message: 'Something went wrong', error });
	}
};


export const profileDelete = async (req: Request, res: Response): Promise<any> => {
	try {
		const userId = req.user?._id;

		if (!userId) return res.status(401).json({ error: 'Пользователь не авторизован' });

		await UserModel.findByIdAndDelete(userId);

		res.clearCookie('accessToken');
		res.clearCookie('refreshToken');

		return res.status(200).json({ message: 'Пользователь удалён' });
	} catch (error) {
		console.error(error);
		res.status(500).json({ error: 'Ошибка при удалении пользователя' });
	}
};