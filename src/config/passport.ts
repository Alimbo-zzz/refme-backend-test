import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import AppleStrategy from 'passport-apple';
import { UserModel } from '@/models';
import { IProviderAccount, IUser } from '@/types';
import { Request } from 'express';
import fs from 'fs';
import path from 'path';
// import { Profile } from 'passport-google-oauth20';
// import { VerifyCallback } from 'passport-oauth2';


const {
	GOOGLE_CLIENT_ID,
	GOOGLE_CLIENT_SECRET,
	GOOGLE_CALLBACK_URL,
	APPLE_CLIENT_ID,
	APPLE_TEAM_ID,
	APPLE_KEY_ID,
	APPLE_PRIVATE_KEY_PATH,
	APPLE_CALLBACK_URL,
} = process.env;

// Сериализация пользователя
passport.serializeUser((user: any, done) => {
	done(null, user.id);
});

// Десериализация пользователя
passport.deserializeUser(async (id, done) => {
	try {
		const user = await UserModel.findById(id);
		done(null, user);
	} catch (err) {
		done(err);
	}
});



// Google Strategy
passport.use(new GoogleStrategy({
	clientID: GOOGLE_CLIENT_ID!,
	clientSecret: GOOGLE_CLIENT_SECRET!,
	callbackURL: GOOGLE_CALLBACK_URL!,
	passReqToCallback: true, // 👈 ОБЯЗАТЕЛЬНО
}, async (req: Request, _accessToken, _refreshToken, profile, done) => {
	try {
		const googleAccount: IProviderAccount = {
			provider: 'google',
			providerId: profile.id,
			email: profile.emails?.[0].value,
		};

		// Если пользователь уже вошёл — просто добавляем ему провайдер
		if (req.user) {
			const user = await UserModel.findById(req.user._id);

			const alreadyLinked = user?.providerAccounts.some(
				acc => acc.provider === 'google' && acc.providerId === profile.id
			);

			if (!alreadyLinked) {
				user?.providerAccounts.push(googleAccount);
				await user?.save();
			}

			return done(null, user as Express.User);
		}

		// Ищем по Google ID
		const user = await UserModel.findOne({
			providerAccounts: {
				$elemMatch: {
					provider: 'google',
					providerId: profile.id
				}
			}
		});

		if (user) return done(null, user);

		// Иначе создаём нового пользователя
		const newUser = await UserModel.create({
			email: profile.emails?.[0].value,
			name: profile.displayName,
			avatar: profile.photos?.[0].value,
			providerAccounts: [googleAccount],
			emailVerified: true,
		});

		return done(null, newUser);
	} catch (err) {
		return done(err);
	}
}));



// Apple Strategy

const appleConfig = {
	clientID: APPLE_CLIENT_ID!,
	teamID: APPLE_TEAM_ID!,
	keyID: APPLE_KEY_ID!,
	key: fs.readFileSync(path.resolve(APPLE_PRIVATE_KEY_PATH!)),
	scope: ['name', 'email'],
	callbackURL: APPLE_CALLBACK_URL!,
	passReqToCallback: true,
};

passport.use(new (AppleStrategy as any)(appleConfig, async (
	req: Request,
	accessToken: string,
	refreshToken: string,
	idToken: string,
	profile: any,
	done: (error: any, user?: any) => void
) => {
	try {
		// Apple отправляет профиль только при первом входе
		const { sub: appleId, email } = profile;

		const appleAccount: IProviderAccount = {
			provider: 'apple',
			providerId: appleId,
			email: email,
			isPrivateEmail: profile.isPrivateEmail || false,
		};

		// Если пользователь уже вошёл — просто добавляем ему провайдер
		if (req.user) {
			const user = await UserModel.findById((req.user as IUser)._id);

			const alreadyLinked = user?.providerAccounts.some(
				acc => acc.provider === 'apple' && acc.providerId === appleId
			);

			if (!alreadyLinked) {
				user?.providerAccounts.push(appleAccount);
				await user?.save();
			}

			return done(null, user as Express.User);
		}

		// Ищем по Apple ID
		const existingUser = await UserModel.findOne({
			providerAccounts: {
				$elemMatch: {
					provider: 'apple',
					providerId: appleId
				}
			}
		});

		if (existingUser) return done(null, existingUser);

		// Ищем по email (на случай, если пользователь уже есть с другим провайдером)
		if (email) {
			const userByEmail = await UserModel.findOne({
				'providerAccounts.email': email
			});

			if (userByEmail) {
				// Добавляем Apple аккаунт к существующему пользователю
				userByEmail.providerAccounts.push(appleAccount);
				await userByEmail.save();
				return done(null, userByEmail);
			}
		}

		// Создаём нового пользователя
		// Apple может не предоставить имя при последующих входах
		const userName = profile.name ?
			`${profile.name.firstName} ${profile.name.lastName}` :
			'Apple User';

		const newUser = await UserModel.create({
			email: email || `apple_${appleId}@private.appleid.com`,
			name: userName,
			providerAccounts: [appleAccount],
			emailVerified: true,
		});

		return done(null, newUser);
	} catch (err) {
		console.error('Apple OAuth error:', err);
		return done(err);
	}
}));
