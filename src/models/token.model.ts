import mongoose, { Schema, Document, Types } from 'mongoose';
import { IToken } from '@/types';

export interface ITokenDocument extends IToken, Document { }

const tokenSchema = new Schema<ITokenDocument>(
	{
		user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
		refreshToken: { type: String, required: true, unique: true },
		expiresAt: { type: Date, required: true },

		ip: { type: String, required: false },
		userAgent: { type: String, required: false },
		isValid: { type: Boolean, default: true },
	},
	{ timestamps: { createdAt: true, updatedAt: false } }
);

// TTL индекс для автоматического удаления просроченных токенов
tokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const TokenModel = mongoose.model<ITokenDocument>('token', tokenSchema);
