import { Router } from 'express';
import { authController } from '../controllers/auth';
import { jwksController } from '../controllers/jwks';
import {
   authenticateToken,
   requireAdmin,
   loginRateLimit,
   passwordResetRateLimit,
   registerRateLimit,
   generalRateLimit
} from '../middleware';

const router = Router();

// Apply general rate limiting to all routes
router.use(generalRateLimit);

// Public routes
router.post('/register', registerRateLimit, authController.register.bind(authController));
router.post('/login', loginRateLimit, authController.login.bind(authController));
router.post('/login/mobile', loginRateLimit, authController.mobileLogin.bind(authController));
router.post('/google', loginRateLimit, authController.googleOAuth.bind(authController));
router.post('/refresh', authController.refreshToken.bind(authController));
router.post('/logout', authController.logout.bind(authController));
router.post('/verify-email', authController.verifyEmail.bind(authController));
router.post('/forgot-password', passwordResetRateLimit, authController.forgotPassword.bind(authController));
router.post('/reset-password', authController.resetPassword.bind(authController));

// JWKS endpoint (public, no authentication required)
router.get('/.well-known/jwks.json', jwksController.getJWKS.bind(jwksController));

// Health check endpoint
router.get('/health', jwksController.healthCheck.bind(jwksController));

// Protected routes (require authentication)
router.get('/me', authenticateToken, authController.getMe.bind(authController));
router.get('/user/:userId', authenticateToken, authController.getRole.bind(authController));
router.post('/change-password', authenticateToken, authController.changePassword.bind(authController));

// Admin only routes
router.post('/revoke', authenticateToken, requireAdmin, authController.revokeToken.bind(authController));
router.post('/emergency-revoke', authenticateToken, requireAdmin, authController.emergencyRevoke.bind(authController));

export default router;
