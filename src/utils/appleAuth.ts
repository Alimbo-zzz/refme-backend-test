import jwt from 'jsonwebtoken';

export const generateAppleClientSecret = (): string => {
	const {
		APPLE_TEAM_ID,
		APPLE_CLIENT_ID,
		APPLE_KEY_ID,
		APPLE_PRIVATE_KEY
	} = process.env;

	if (!APPLE_TEAM_ID || !APPLE_CLIENT_ID || !APPLE_KEY_ID || !APPLE_PRIVATE_KEY) {
		throw new Error('Missing Apple OAuth configuration');
	}

	const now = Math.floor(Date.now() / 1000);

	const payload = {
		iss: APPLE_TEAM_ID,
		iat: now,
		exp: now + 3600, // 1 hour
		aud: 'https://appleid.apple.com',
		sub: APPLE_CLIENT_ID,
	};

	return jwt.sign(payload, APPLE_PRIVATE_KEY.replace(/\\n/g, '\n'), {
		algorithm: 'ES256',
		keyid: APPLE_KEY_ID,
	});
};

export const decodeAppleIdToken = (idToken: string): any => {
	try {
		const payload = idToken.split('.')[1];
		const decoded = Buffer.from(payload, 'base64').toString();
		return JSON.parse(decoded);
	} catch (error) {
		throw new Error('Invalid Apple ID token');
	}
};