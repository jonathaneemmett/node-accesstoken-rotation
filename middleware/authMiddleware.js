import jwt from 'jsonwebtoken';
import asyncErrorHandler from '../utils/asyncErrorHandler.js';
import prisma from '../config/dbPostgres.js';

const protectRoute = asyncErrorHandler(async (req, res, next) => {
	const { jwt: token, refreshToken } = req.cookies;

	if (!token && !refreshToken) {
		res.status(401);
		throw new Error('No Cookies, Not authorized');
	}

	try {
		const decoded = await jwt.verify(token, process.env.JWT_SECRET);
		if (!decoded) {
			res.status(401);
			throw new Error('No Token, Not authorized');
		}
		const { userId } = decoded;
		const user = await prisma.user.findUnique({ where: { id: userId } });
		if (!user) {
			res.status(401);
			throw new Error('No User, Not authorized');
		}

		// Check access token
		const refreshTokenDecoded = await jwt.verify(
			refreshToken,
			user.context,
		);
		if (!refreshTokenDecoded) {
			res.status(401);
			throw new Error('No RefreshToken, Not authorized');
		}

		req.user = user;
		next();
	} catch (err) {
		res.status(401);
		console.error('err', err);
		throw new Error('Just Broken, Not authorized');
	}
});

const adminRoute = asyncErrorHandler(async (req, res, next) => {
	if (req.user && req.user.role.toLowerCase() === 'admin') {
		next();
	} else {
		res.status(401);
		throw new Error('Not an admin, Not authorized');
	}
});

export { protectRoute, adminRoute };
