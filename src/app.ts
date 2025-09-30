import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import morgan from 'morgan';

import routes from '@/routes';
import { errorHandler } from './middleware';
import path from 'path';

const app = express();

app.use(express.static(path.join(__dirname, '../public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(cors({ origin: true, credentials: true }));
app.use(morgan('dev'));

// Подключаем маршруты
app.use('/api', routes);

app.get('/', (req, res) => {
	res.sendFile(path.join(__dirname, '../public/index.html'));
});



// Подключаем обработку ошибок
app.use(errorHandler);

export default app;
