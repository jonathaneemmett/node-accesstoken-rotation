import { Router } from 'express';
import {
	login,
	register,
	logout,
	refreshToken,
} from '../controllers/authController.js';
import { protectRoute } from '../middleware/authMiddleware.js';

const router = Router();

router.post('/register', register);
router.post('/login', login);
router.post('/refreshToken/:id', refreshToken);
router.post('/logout', protectRoute, logout);

export default router;
