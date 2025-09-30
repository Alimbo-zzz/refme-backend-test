import mongoose, { Schema } from 'mongoose';
import { IUser, IProviderAccount } from '@/types';

const providerAccountSchema = new Schema<IProviderAccount>(
	{
		provider: {
			type: String,
			enum: ['google', 'apple'],
			required: true,
		},
		providerId: {
			type: String,
			required: true,
		},
		email: {
			type: String,
		},
		isPrivateEmail: {
			type: Boolean,
		}
	},
	{ _id: false } // чтобы не создавать отдельный _id для каждого providerAccount
);

const userSchema = new Schema<IUser>(
	{
		email: { type: String, unique: true, sparse: true },
		login: { type: String, unique: true, sparse: true },
		password: { type: String },

		name: { type: String },
		avatar: { type: String },

		providerAccounts: [providerAccountSchema],

		emailVerified: { type: Boolean, default: false }
	},
	{ timestamps: true }
);

export const UserModel = mongoose.model<IUser>('user', userSchema);
