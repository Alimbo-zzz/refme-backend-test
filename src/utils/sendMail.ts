import nodemailer, { Transporter, SendMailOptions } from 'nodemailer';

const {
	SMTP_USER,
	SMTP_PASS,
	SMTP_HOST,
	SMTP_PORT,
	SMTP_SECURE
} = process.env;

interface IMainOps {
	subject?: string,
	text?: string,
	html?: string
}

export const sendEmail = async (to: string, ops?: IMainOps) => {

	const transporter: Transporter = nodemailer.createTransport({
		host: SMTP_HOST!,
		port: Number(SMTP_PORT),
		secure: SMTP_SECURE === 'true',
		auth: {
			user: SMTP_USER!,
			pass: SMTP_PASS!,
		},
		tls: {
			ciphers: 'TLS_AES_256_GCM_SHA384', // Как в curl
			minVersion: 'TLSv1.3'
		},
		connectionTimeout: 60000,
		socketTimeout: 60000
	});

	const mailOptions: SendMailOptions = {
		from: `"RefMe" <${SMTP_USER}>`,
		to,
		...ops
	};

	await transporter.sendMail(mailOptions);
};