import mongoose, { Schema } from 'mongoose';
import { IPasswordResetToken } from '@/types';

const passwordResetSchema = new Schema<IPasswordResetToken>(
	{
		user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
		resetToken: { type: String, required: true, unique: true },
		expiresAt: { type: Date, required: true },
	},
	{ timestamps: true }
);

passwordResetSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const PasswordResetModel = mongoose.model<IPasswordResetToken>('password-reset-token', passwordResetSchema);
