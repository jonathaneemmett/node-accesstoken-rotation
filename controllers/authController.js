import asyncErrorHandler from '../utils/asyncErrorHandler.js';
import prisma from '../config/dbPostgres.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

import { generateTokens } from '../utils/generateTokens.js';

export const register = asyncErrorHandler(async (req, res) => {
	const { email, password } = req.body;

	// Simple validation
	if (!email || !password) {
		res.status(400);
		throw new Error('All fields are required');
	}

	// Check if user exists
	const existingUser = await prisma.user.findUnique({ where: { email } });
	if (existingUser) {
		res.status(400);
		throw new Error('Email address already in use. Please try again.');
	}

	// Create new user
	const newUser = {
		email,
		password: await bcrypt.hash(password, 10),
	};

	const user = await prisma.user.create({ data: newUser });

	if (user) {
		const { token, refreshToken } = await generateTokens(res, user.id);

		res.cookie('jwt', token, {
			path: '/',
			httpOnly: true,
			sameSite: 'lax',
			// secure: process.env.NODE_ENV === 'production',
			maxAge: 15 * 60 * 1000, // 15 minutes
		});

		res.cookie('refreshToken', refreshToken, {
			path: '/',
			httpOnly: true,
			sameSite: 'lax',
			// secure: process.env.NODE_ENV === 'production',
			maxAge: 60 * 60 * 25 * 1000, // 1 day
		});

		res.status(201).json({
			id: user.id,
			email: user.email,
		});
	} else {
		res.status(400);
		throw new Error('Invalid user data');
	}
});

export const login = asyncErrorHandler(async (req, res) => {
	const { email, password } = req.body;

	// Simple validation
	if (!email || !password) {
		res.status(400);
		throw new Error('All fields are required');
	}

	// Check if user exists
	const user = await prisma.user.findUnique({ where: { email } });

	if (user && (await bcrypt.compare(password, user.password))) {
		const { token, refreshToken } = await generateTokens(res, user.id);

		res.cookie('jwt', token, {
			path: '/',
			httpOnly: true,
			sameSite: 'lax',
			// secure: process.env.NODE_ENV === 'production',
			maxAge: 15 * 60 * 1000, // 15 minutes
		});

		res.cookie('refreshToken', refreshToken, {
			path: '/',
			httpOnly: true,
			sameSite: 'lax',
			// secure: process.env.NODE_ENV === 'production',
			maxAge: 60 * 60 * 25 * 1000, // 1 day
		});

		res.status(201).json({
			id: user.id,
			email: user.email,
			role: user.role,
		});
	} else {
		res.status(401);
		throw new Error('Invalid email or password');
	}
});

export const logout = asyncErrorHandler(async (req, res) => {
	res.cookie('refreshToken', '', {
		httpOnly: true,
		maxAge: new Date(0),
	});

	res.cookie('jwt', '', {
		httpOnly: true,
		maxAge: new Date(0),
	});
	res.status(200).json({ message: 'Logged out successfully' });
});

export const refreshToken = asyncErrorHandler(async (req, res) => {
	// get the cookie
	const refreshToken = req.cookies.refreshToken;
	if (!refreshToken) {
		res.status(401);
		throw new Error('No refresh token');
	}

	// Clear the cookie
	res.clearCookie('refreshToken', {
		path: '/',
		httpOnly: true,
		sameSite: 'lax',
		// secure: process.env.NODE_ENV === 'production',
		maxAge: new Date(0),
	});

	// get the user
	const foundUser = await prisma.user.findUnique({
		where: {
			refreshTokens: {
				has: refreshToken,
			},
		},
	});

	if (!foundUser) {
		// Detected a refresh token reuse attack
		jwt.verify(
			refreshToken,
			process.env.REFRESH_TOKEN_SECRET,
			async (err, decoded) => {
				if (err) {
					res.status(403);
					throw new Error('Invalid refresh token');
				}
				const hackedUser = await prisma.user.findUnique({
					where: { id: decoded.id },
				});
				if (hackedUser) {
					hackedUser.refreshTokens = [];
					const result = await prisma.user.update({
						where: { id: decoded.id },
						data: hackedUser,
					});
				}

				res.status(403);
				throw new Error('Invalid refresh token');
			},
		);
	}

	// Filter out the old refresh token
	const newRefreshTokens = foundUser.refreshTokens.filter(
		(rt) => rt !== refreshToken,
	);

	jwt.verify(
		refreshToken,
		process.env.REFRESH_TOKEN_SECRET,
		async (err, decoded) => {
			if (err) {
				// expired token
				foundUser.refreshTokens = [...newRefreshTokens];
				const result = await prisma.user.update({
					where: { id: decoded.id },
					data: foundUser,
				});
			}

			if (err || foundUser.id !== decoded.id) {
				res.status(403);
				throw new Error('Invalid refresh token');
			}

			// generate new tokens
			const { token, refreshToken: newRefreshToken } =
				await generateTokens(res, foundUser.id);

			// add the new refresh token to the user
			foundUser.refreshTokens = [...newRefreshTokens, newRefreshToken];
			const result = await prisma.user.update({
				where: { id: decoded.id },
				data: foundUser,
			});

			res.cookie('jwt', token, {
				path: '/',
				httpOnly: true,
				sameSite: 'lax',
				// secure: process.env.NODE_ENV === 'production',
				maxAge: 15 * 60 * 1000, // 15 minutes
			});

			res.cookie('refreshToken', newRefreshToken, {
				path: '/',
				httpOnly: true,
				sameSite: 'lax',
				// secure: process.env.NODE_ENV === 'production',
				maxAge: 60 * 60 * 25 * 1000, // 1 day
			});

			res.status(201).json({
				id: foundUser.id,
				email: foundUser.email,
				role: foundUser.role,
			});
		},
	);
});
