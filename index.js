import express from 'express';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import { notFound, errorHandler } from './middleware/errorMiddleware.js';

// Routes
import authRoutes from './routes/authRoutes.js';

dotenv.config();

const PORT = process.env.PORT || 5100;

const app = express();
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* Routes */
app.use('/api/auth', authRoutes);

// Catch all
app.get('*', (req, res) => {
	res.send('Api is running, you lucky duck.');
});
app.use(notFound);
app.use(errorHandler);

app.listen(PORT, () => {
	console.log(`Server running on port ${PORT}`);
});
