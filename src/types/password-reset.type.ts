import { Document, Types } from 'mongoose';

export interface IPasswordResetToken extends Document {
	user: Types.ObjectId;
	resetToken: string;      // уникальный токен
	expiresAt: Date;         // срок жизни токена
	createdAt: Date;
}
