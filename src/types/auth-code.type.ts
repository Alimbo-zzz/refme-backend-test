import { Types } from 'mongoose';

export interface IAuthCode {
	user: Types.ObjectId;
	code: string;
	expiresAt: Date;
}