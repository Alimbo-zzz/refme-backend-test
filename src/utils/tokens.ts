import jwt from 'jsonwebtoken';
import ms from 'ms';
import { Response } from 'express';


const {
	REFRESH_TOKEN_EXPIRES_IN,
	ACCESS_TOKEN_EXPIRES_IN,
	JWT_ACCESS_SECRET,
	JWT_REFRESH_SECRET,
}: any = process.env;


export const parseTimeToMs = (timeStr: string): number => {
	const match = timeStr.match(/^(\d+)([smhd])$/); // s, m, h, d
	if (!match) throw new Error(`Invalid time format: ${timeStr}`);

	const value = parseInt(match[1], 10);
	const unit = match[2];

	const multipliers: Record<string, number> = {
		s: 1000,
		m: 60 * 1000,
		h: 60 * 60 * 1000,
		d: 24 * 60 * 60 * 1000,
	};

	return value * multipliers[unit];
};

export const setAuthCookies = (res: Response, accessToken: string, refreshToken: string) => {
	const accessTokenMaxAge = parseTimeToMs(process.env.ACCESS_TOKEN_EXPIRES_IN || '15m');
	const refreshTokenMaxAge = parseTimeToMs(process.env.REFRESH_TOKEN_EXPIRES_IN || '30d');

	res.cookie('accessToken', accessToken, {
		httpOnly: true,
		secure: process.env.NODE_ENV === 'production',
		sameSite: 'strict',
		maxAge: accessTokenMaxAge
	});

	res.cookie('refreshToken', refreshToken, {
		httpOnly: true,
		secure: process.env.NODE_ENV === 'production',
		sameSite: 'strict',
		maxAge: refreshTokenMaxAge
	});
};


export const getRefreshTokenExpiryDate = () => {
	return new Date(Date.now() + ms(REFRESH_TOKEN_EXPIRES_IN));
};

export const generateTokens = (userId: string) => {
	const accessToken = jwt.sign(
		{ userId } as jwt.JwtPayload,
		JWT_ACCESS_SECRET,
		{ expiresIn: ACCESS_TOKEN_EXPIRES_IN }
	);

	const refreshToken = jwt.sign(
		{ userId } as jwt.JwtPayload,
		JWT_REFRESH_SECRET,
		{ expiresIn: REFRESH_TOKEN_EXPIRES_IN }
	);

	const refreshTokenExpiresAt = getRefreshTokenExpiryDate();

	return { accessToken, refreshToken, refreshTokenExpiresAt };
};
