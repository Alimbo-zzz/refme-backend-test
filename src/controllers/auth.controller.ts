import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import { UserModel } from '@/models/user.model';
import { generateTokens } from '@/utils/tokens';  // твоя функция генерации access и refresh токенов
import { TokenModel } from '@/models';
import { generateCode, sendEmail, setAuthCookies } from '@/utils';
import { AuthCodeModel } from '@/models/auth-code.model';
import jwt from 'jsonwebtoken';
import qs from 'qs';
import axios from 'axios';
import { IProviderAccount } from '@/types';


export const register = async (req: Request, res: Response): Promise<any> => {
	try {
		const { email, password, name } = req.body;

		if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

		const existingUser = await UserModel.findOne({ email });
		if (existingUser) return res.status(409).json({ message: 'User already exists' });

		const hashedPassword = await bcrypt.hash(password, 12);

		const user = new UserModel({
			email,
			password: hashedPassword,
			name,
		});

		await user.save();


		// Генерируем 5-значный код
		const code = generateCode(4);

		await AuthCodeModel.findOneAndUpdate(
			{ user: user._id },
			{
				code,
				expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 минут
			},
			{ upsert: true }
		);

		sendEmail(email, { subject: 'RefMe verify code', text: `Your verification code is: ${code}` });

		// // Код на почте
		return res.status(201).json({ message: 'Registration successful. Check your email for verification code.' });

	} catch (err) {
		console.error(err);
		return res.status(500).json({ message: 'Internal server error' });
	}
};


export const resendVerifyCode = async (req: Request, res: Response): Promise<any> => {
	try {
		const { email } = req.body;

		if (!email) return res.status(400).json({ message: 'Email is required' });
		// Находим пользователя по email
		const user = await UserModel.findOne({ email });
		if (!user) return res.status(404).json({ message: 'User not found' });
		// Генерируем новый код
		const code = generateCode(4);
		// Сохраняем или обновляем код подтверждения в базе
		await AuthCodeModel.findOneAndUpdate(
			{ user: user._id },
			{
				code,
				expiresAt: new Date(Date.now() + 5 * 60 * 1000), // код действует 5 минут
			},
			{ upsert: true, new: true }
		);
		// Отправляем письмо с новым кодом
		await sendEmail(email, { subject: 'RefMe verify code', text: `Your verification code is: ${code}` });

		return res.status(200).json({ message: 'Verification code resent' });
	} catch (err) {
		console.error(err);
		return res.status(500).json({ message: 'Internal server error' });
	}
};


export const verifyCode = async (req: Request, res: Response): Promise<any> => {
	const { email, code } = req.body;
	if (!email || !code) return res.status(400).json({ message: 'Email and code are required' });

	const user = await UserModel.findOne({ email });
	if (!user) return res.status(404).json({ message: 'User not found' });

	const authCode = await AuthCodeModel.findOne({
		user: user._id,
		code,
		expiresAt: { $gt: new Date() }, // не истек
	});

	if (!authCode) return res.status(400).json({ message: 'Invalid or expired code' });

	// делаем код невалидным, чтобы нельзя было повторно использовать
	user.emailVerified = true;
	await user.save();
	await authCode.deleteOne();
	const { accessToken, refreshToken, refreshTokenExpiresAt } = generateTokens((user._id as any).toString());

	setAuthCookies(res, accessToken, refreshToken);

	await TokenModel.create({
		user: user._id,
		refreshToken,
		expiresAt: refreshTokenExpiresAt,
		ip: req.ip, // автоматом берет IP из запроса
		userAgent: req.headers['user-agent'], // строка браузера/устройства
	});


	res.json({ accessToken, refreshToken, refreshTokenExpiresAt });
};


export const logout = async (req: Request, res: Response): Promise<any> => {
	try {
		const refreshToken = req.cookies?.refreshToken || req.headers.authorization?.split(' ')[1];

		if (!refreshToken) return res.status(200).json({ message: 'Already logged out' });

		// Удаляем токен из базы
		await TokenModel.findOneAndDelete({ refreshToken });

		// Очищаем куки
		res.clearCookie('accessToken', { httpOnly: true, secure: true, sameSite: 'strict' });
		res.clearCookie('refreshToken', { httpOnly: true, secure: true, sameSite: 'strict' });

		return res.status(200).json({ message: 'Logged out successfully' });
	} catch (err) {
		console.error('Logout error:', err);
		return res.status(500).json({ message: 'Internal server error' });
	}
};


export const refreshToken = async (req: Request, res: Response): Promise<any> => {
	try {
		const refreshToken = req.cookies?.refreshToken || req.headers.authorization?.split(' ')[1];

		if (!refreshToken) return res.status(401).json({ message: 'No refresh token provided' });

		// Проверяем токен на подпись
		let payload: any;
		try {
			payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET!);
		} catch (err) {
			return res.status(401).json({ message: 'Invalid refresh token' });
		}

		// Проверяем наличие токена в базе
		const existingToken = await TokenModel.findOne({ refreshToken });
		if (!existingToken || !existingToken.isValid) return res.status(401).json({ message: 'Refresh token not found or invalidated' });

		// Проверяем, существует ли пользователь
		const user = await UserModel.findById(payload.userId);
		if (!user) return res.status(404).json({ message: 'User not found' });

		// Генерируем новые токены
		const { accessToken, refreshToken: newRefreshToken, refreshTokenExpiresAt } = generateTokens((user._id as any).toString());

		// Обновляем refresh токен в базе
		existingToken.refreshToken = newRefreshToken;
		existingToken.expiresAt = refreshTokenExpiresAt;
		await existingToken.save();

		// Ставим новые куки
		setAuthCookies(res, accessToken, newRefreshToken);

		res.status(200).json({ message: 'Tokens refreshed', tokens: { accessToken, refreshToken: newRefreshToken } });
	} catch (err) {
		console.error(err);
		res.status(500).json({ message: 'Internal server error' });
	}
};


export const login = async (req: Request, res: Response): Promise<any> => {
	try {
		const { email, password } = req.body;

		if (!email || !password) return res.status(400).json({ message: 'Email and password are required' });

		const user = await UserModel.findOne({ email });
		if (!user) return res.status(401).json({ message: 'Invalid credentials' });


		const isMatch = await bcrypt.compare(password, (user.password as any));
		if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });


		if (!user?.emailVerified) {
			// Генерируем 5-значный код
			const code = generateCode(5);

			await AuthCodeModel.findOneAndUpdate(
				{ user: user._id },
				{
					code,
					expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 минут
				},
				{ upsert: true }
			);

			sendEmail(email, { subject: 'RefMe verify code', text: `Your verification code is: ${code}` });
			return res.status(401).json({ message: `Mail is not confirmed, the new code is sent to the mail ${email}` });
		}

		// Можно добавить проверку, активирован ли пользователь
		const { accessToken, refreshToken } = generateTokens((user._id as any).toString());

		setAuthCookies(res, accessToken, refreshToken);

		res.json({ message: 'Logged in successfully', tokens: { accessToken, refreshToken } });
	} catch (err) {
		console.error(err);
		res.status(500).json({ message: 'Internal server error' });
	}
};




export const authGoogle = async (req: Request, res: Response): Promise<any> => {
	const CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
	const REDIRECT_URI = process.env.GOOGLE_CALLBACK_URL!;

	try {
		const returnTo = req.headers.referer || '/'; // Получаем URL предыдущей страницы
		const url = 'https://accounts.google.com/o/oauth2/v2/auth?' + qs.stringify({
			client_id: CLIENT_ID,
			redirect_uri: REDIRECT_URI,
			response_type: 'code',
			scope: 'openid email profile',
			access_type: 'offline',
			prompt: 'consent',
			state: returnTo, // Сохраняем URL для редиректа
		});
		res.redirect(url);
	} catch (err) {
		console.error(err);
		res.status(500).json({ message: 'Internal server error' });
	}
};


export const callbackGoogle = async (req: Request, res: Response): Promise<any> => {
	const CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
	const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;
	const REDIRECT_URI = process.env.GOOGLE_CALLBACK_URL!;
	const JWT_SECRET = process.env.JWT_SECRET!;

	const { code, state } = req.query;
	if (!code) return res.status(400).send('Code not found');

	try {
		const { data: tokenData } = await axios.post('https://oauth2.googleapis.com/token', {
			code,
			client_id: CLIENT_ID,
			client_secret: CLIENT_SECRET,
			redirect_uri: REDIRECT_URI,
			grant_type: 'authorization_code',
		});

		const { data: userInfo } = await axios.get('https://www.googleapis.com/oauth2/v3/userinfo', {
			headers: {
				Authorization: `Bearer ${tokenData.access_token}`,
			},
		});

		const googleId = userInfo.sub;
		const email = userInfo.email;
		const name = userInfo.name;
		const avatar = userInfo.picture;

		let user = await UserModel.findOne({
			providerAccounts: {
				$elemMatch: {
					provider: 'google',
					providerId: googleId,
				},
			},
		});

		if (!user) {
			// Если нет — создаём нового
			user = new UserModel({
				name,
				avatar,
				providerAccounts: [
					{
						provider: 'google',
						providerId: googleId,
						email,
					},
				],
			});
			await user.save();
		} else {
			// Обновим общие данные, если они изменились
			if (!user?.name) user.name = name;
			if (!user?.avatar) user.avatar = avatar;

			// Убедимся, что google аккаунт есть в providerAccounts
			const hasGoogle = user.providerAccounts.some(
				(acc) => acc.provider === 'google' && acc.providerId === googleId
			);

			if (!hasGoogle) {
				user.providerAccounts.push({
					provider: 'google',
					providerId: googleId,
					email,
				});
			}

			await user.save();
		}

		// Генерируем JWT
		const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

		// Устанавливаем токен в куки
		res.cookie('authToken', token, {
			httpOnly: true,
			secure: true,
			sameSite: 'lax',
			maxAge: 7 * 24 * 60 * 60 * 1000, // 7 дней
			path: '/',
		});

		// Редирект на фронтенд
		return res.redirect(state?.toString() || '/');
	} catch (err) {
		console.error(err);
		res.status(500).json({ message: 'Internal server error' });
	}
}



export const authApple = async (req: Request, res: Response): Promise<any> => {
	const CLIENT_ID = process.env.APPLE_CLIENT_ID!;
	const REDIRECT_URI = process.env.APPLE_CALLBACK_URL!;
	const TEAM_ID = process.env.APPLE_TEAM_ID!;
	const KEY_ID = process.env.APPLE_KEY_ID!;

	try {
		const returnTo = req.headers.referer || '/';

		// Генерируем state для безопасности
		const state = JSON.stringify({
			returnTo,
			nonce: Math.random().toString(36).substring(2, 15)
		});

		const url = 'https://appleid.apple.com/auth/authorize?' + qs.stringify({
			client_id: CLIENT_ID,
			redirect_uri: REDIRECT_URI,
			response_type: 'code',
			response_mode: 'form_post', // Apple требует form_post
			scope: 'name email',
			state: Buffer.from(state).toString('base64'), // Кодируем state
		});

		res.redirect(url);
	} catch (err) {
		console.error('Apple auth error:', err);
		res.status(500).json({ message: 'Internal server error' });
	}
};

export const callbackApple = async (req: Request, res: Response): Promise<any> => {
	const CLIENT_ID = process.env.APPLE_CLIENT_ID!;
	const TEAM_ID = process.env.APPLE_TEAM_ID!;
	const KEY_ID = process.env.APPLE_KEY_ID!;
	const PRIVATE_KEY = process.env.APPLE_PRIVATE_KEY!;
	const REDIRECT_URI = process.env.APPLE_CALLBACK_URL!;
	const JWT_SECRET = process.env.JWT_SECRET!;
	const { code, state, id_token, user } = req.body; // Apple отправляет данные в body
	const bodyUser = user;

	try {
		if (!code) return res.status(400).send('Code not found');

		// Декодируем state
		let decodedState;
		try {
			decodedState = JSON.parse(Buffer.from(state as string, 'base64').toString());
		} catch {
			decodedState = { returnTo: '/' };
		}

		// Создаем client_secret JWT для Apple
		const clientSecret = jwt.sign(
			{
				iss: TEAM_ID,
				iat: Math.floor(Date.now() / 1000),
				exp: Math.floor(Date.now() / 1000) + 3600, // 1 час
				aud: 'https://appleid.apple.com',
				sub: CLIENT_ID,
			},
			PRIVATE_KEY.replace(/\\n/g, '\n'), // Важно: заменяем \n на настоящие переносы строк
			{
				algorithm: 'ES256',
				keyid: KEY_ID,
			}
		);

		// Получаем access token от Apple
		const { data: tokenData } = await axios.post(
			'https://appleid.apple.com/auth/token',
			qs.stringify({
				client_id: CLIENT_ID,
				client_secret: clientSecret,
				code,
				grant_type: 'authorization_code',
				redirect_uri: REDIRECT_URI,
			}),
			{
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded',
				},
			}
		);

		// Декодируем id_token чтобы получить данные пользователя
		const idTokenPayload = JSON.parse(
			Buffer.from(tokenData.id_token.split('.')[1], 'base64').toString()
		);

		const appleId = idTokenPayload.sub;
		const email = idTokenPayload.email;

		// Apple может не предоставить email, если пользователь выбрал приватность
		let userName = 'Apple User';
		let userEmail = email;

		// Пытаемся получить имя из параметра user (только при первом входе)
		if (bodyUser) {
			try {
				const userData = JSON.parse(bodyUser as string);
				if (userData.name) {
					const { firstName, lastName } = userData.name;
					userName = `${firstName} ${lastName}`.trim();
				}
			} catch (e) {
				console.log('No user name data from Apple');
			}
		}

		// Если email не предоставлен, создаем placeholder
		if (!userEmail) {
			userEmail = `apple_${appleId}@private.appleid.com`;
		}

		// Ищем пользователя по Apple ID
		let user = await UserModel.findOne({
			providerAccounts: {
				$elemMatch: {
					provider: 'apple',
					providerId: appleId,
				},
			},
		});

		if (!user) {
			// Проверяем, есть ли пользователь с таким email
			user = await UserModel.findOne({ email: userEmail });

			if (user) {
				// Добавляем Apple аккаунт к существующему пользователю
				const appleAccount: IProviderAccount = {
					provider: 'apple',
					providerId: appleId,
					email: userEmail,
					isPrivateEmail: !email, // Если email не предоставлен - это приватный email
				};

				user.providerAccounts.push(appleAccount);
				await user.save();
			} else {
				// Создаем нового пользователя
				user = new UserModel({
					name: userName,
					email: userEmail,
					providerAccounts: [
						{
							provider: 'apple',
							providerId: appleId,
							email: userEmail,
							isPrivateEmail: !email, // Если email не предоставлен - это приватный email
						},
					],
					emailVerified: true, // Apple проверяет email
				});
				await user.save();
			}
		} else {
			// Обновляем данные существующего пользователя
			if (!user.name || user.name === 'Apple User') {
				user.name = userName;
			}

			// Обновляем email если он изменился или был приватным
			if (email && user?.email?.includes('@private.appleid.com')) {
				user.email = email;
			}

			// Убедимся, что Apple аккаунт есть в providerAccounts
			const hasApple = user.providerAccounts.some(
				(acc) => acc.provider === 'apple' && acc.providerId === appleId
			);

			if (!hasApple) {
				user.providerAccounts.push({
					provider: 'apple',
					providerId: appleId,
					email: userEmail,
					isPrivateEmail: !email,
				});
			}

			await user.save();
		}

		// Генерируем JWT
		const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
			expiresIn: '7d'
		});

		// Устанавливаем токен в куки
		res.cookie('authToken', token, {
			httpOnly: true,
			secure: process.env.NODE_ENV === 'production',
			sameSite: 'lax',
			maxAge: 7 * 24 * 60 * 60 * 1000, // 7 дней
			path: '/',
		});

		// Редирект на фронтенд
		return res.redirect(decodedState.returnTo || '/');
	} catch (err) {
		console.error('Apple callback error:', err);

		// Более детальная обработка ошибок
		if (axios.isAxiosError(err)) {
			console.error('Apple API error:', err.response?.data);
		}

		res.status(500).json({ message: 'Internal server error' });
	}
};