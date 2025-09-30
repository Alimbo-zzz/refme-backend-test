import { Document, Types } from 'mongoose';

export interface IProviderAccount {
	provider: 'google' | 'apple';
	providerId: string; // sub или user id от провайдера
	email?: string;     // email с которым входил через провайдера
	isPrivateEmail?: boolean;	// Для Apple могут понадобиться дополнительные поля
}


export interface IUser extends Document {
	email?: string;
	login?: string;
	password?: string;
	providerAccounts: IProviderAccount[];
	name?: string;
	avatar?: string;
	createdAt: Date;
	emailVerified?: Boolean;
}



declare global {
	namespace Express {
		interface User extends IUser { }
	}
}