import mongoose from 'mongoose';
const { DB_HOST, DB_PORT, DB_USERNAME, DB_PASSWORD, DB_NAME } = process.env;

const MONGO_URI = `mongodb://${DB_USERNAME}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}?authSource=admin`;

export async function connectDB(): Promise<void> {
	try {
		await mongoose.connect(MONGO_URI);
		console.log('MongoDB connected');
	} catch (error) {
		console.error('MongoDB connection error:', error);
		process.exit(1);
	}
}