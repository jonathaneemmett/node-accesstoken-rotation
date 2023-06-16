import jwt from 'jsonwebtoken';
import prisma from '../config/dbPostgres.js';

export async function generateTokens(res, userId) {
	const token = await jwt.sign({ userId }, process.env.JWT_SECRET, {
		expiresIn: '15m',
	});

	const refreshToken = await jwt.sign(
		{ userId },
		process.env.REFRESH_TOKEN_SECRET,
		{
			expiresIn: '7d',
		},
	);

	return { token, refreshToken };
}
