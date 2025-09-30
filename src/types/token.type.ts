import { Document, Types } from 'mongoose';

export interface IToken extends Document {
	user: Types.ObjectId;
	refreshToken: string;
	expiresAt: Date;
	createdAt: Date;

	ip?: string;
	userAgent?: string;
	isValid?: boolean;
}
