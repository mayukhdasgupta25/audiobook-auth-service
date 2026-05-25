import { Request, Response, NextFunction } from 'express';
import { BillingInterval, SubscriptionStatus } from '@prisma/client';

const CUID_REGEX = /^c[a-z0-9]{24}$/;
const UUID_REGEX =
   /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const ALLOWED_INTERVALS: BillingInterval[] = ['MONTHLY', 'QUARTERLY', 'YEARLY', 'LIFETIME'];
const ALLOWED_STATUSES: SubscriptionStatus[] = [
   'PENDING', 'TRIALING', 'ACTIVE', 'PAST_DUE', 'PAUSED', 'CANCELED', 'EXPIRED',
];

export function validatePagination(req: Request, res: Response, next: NextFunction): void {
   const page = req.query['page'];
   const limit = req.query['limit'];
   if (page !== undefined) {
      const p = parseInt(page as string, 10);
      if (!Number.isInteger(p) || p < 1) {
         res.status(400).json({ error: 'page must be a positive integer' });
         return;
      }
   }
   if (limit !== undefined) {
      const l = parseInt(limit as string, 10);
      if (!Number.isInteger(l) || l < 1 || l > 100) {
         res.status(400).json({ error: 'limit must be between 1 and 100' });
         return;
      }
   }
   next();
}

export function validateCuidParam(paramName: string) {
   return (req: Request, res: Response, next: NextFunction): void => {
      const value = req.params[paramName];
      if (!value || !CUID_REGEX.test(value)) {
         res.status(400).json({ error: `${paramName} must be a valid CUID` });
         return;
      }
      next();
   };
}

export function validateCreatePlan(req: Request, res: Response, next: NextFunction): void {
   const { name, price, currency, billingInterval, trialDays, isActive, description } = req.body || {};
   if (typeof name !== 'string' || name.trim().length === 0 || name.trim().length > 100) {
      res.status(400).json({ error: 'name must be a non-empty string up to 100 characters' });
      return;
   }
   if (typeof price !== 'number' || !Number.isFinite(price) || price < 0) {
      res.status(400).json({ error: 'price must be a non-negative number' });
      return;
   }
   if (currency !== undefined && (typeof currency !== 'string' || currency.length < 3 || currency.length > 8)) {
      res.status(400).json({ error: 'currency must be a 3-8 character ISO code' });
      return;
   }
   if (billingInterval !== undefined && !ALLOWED_INTERVALS.includes(billingInterval)) {
      res.status(400).json({ error: `billingInterval must be one of: ${ALLOWED_INTERVALS.join(', ')}` });
      return;
   }
   if (trialDays !== undefined && (!Number.isInteger(trialDays) || trialDays < 0 || trialDays > 365)) {
      res.status(400).json({ error: 'trialDays must be a non-negative integer up to 365' });
      return;
   }
   if (isActive !== undefined && typeof isActive !== 'boolean') {
      res.status(400).json({ error: 'isActive must be a boolean' });
      return;
   }
   if (description !== undefined && description !== null && (typeof description !== 'string' || description.length > 1000)) {
      res.status(400).json({ error: 'description must be a string up to 1000 characters' });
      return;
   }
   req.body.name = name.trim();
   next();
}

export function validateUpdatePlan(req: Request, res: Response, next: NextFunction): void {
   const { name, price, currency, billingInterval, trialDays, isActive } = req.body || {};
   const allowed = ['name', 'price', 'currency', 'billingInterval', 'trialDays', 'isActive', 'description', 'features'];
   const extra = Object.keys(req.body || {}).filter((k) => !allowed.includes(k));
   if (extra.length > 0) {
      res.status(400).json({ error: `Unexpected fields: ${extra.join(', ')}` });
      return;
   }
   if (Object.keys(req.body || {}).length === 0) {
      res.status(400).json({ error: 'At least one field must be provided for update' });
      return;
   }
   if (name !== undefined) {
      if (typeof name !== 'string' || name.trim().length === 0 || name.trim().length > 100) {
         res.status(400).json({ error: 'name must be a non-empty string up to 100 characters' });
         return;
      }
      req.body.name = name.trim();
   }
   if (price !== undefined && (typeof price !== 'number' || !Number.isFinite(price) || price < 0)) {
      res.status(400).json({ error: 'price must be a non-negative number' });
      return;
   }
   if (currency !== undefined && (typeof currency !== 'string' || currency.length < 3 || currency.length > 8)) {
      res.status(400).json({ error: 'currency must be a 3-8 character ISO code' });
      return;
   }
   if (billingInterval !== undefined && !ALLOWED_INTERVALS.includes(billingInterval)) {
      res.status(400).json({ error: `billingInterval must be one of: ${ALLOWED_INTERVALS.join(', ')}` });
      return;
   }
   if (trialDays !== undefined && (!Number.isInteger(trialDays) || trialDays < 0 || trialDays > 365)) {
      res.status(400).json({ error: 'trialDays must be a non-negative integer up to 365' });
      return;
   }
   if (isActive !== undefined && typeof isActive !== 'boolean') {
      res.status(400).json({ error: 'isActive must be a boolean' });
      return;
   }
   next();
}

export function validateCreateSubscription(req: Request, res: Response, next: NextFunction): void {
   const { userId, planId, autoRenew, paymentMethod, startTrial } = req.body || {};
   if (!planId || typeof planId !== 'string' || !CUID_REGEX.test(planId)) {
      res.status(400).json({ error: 'planId must be a valid CUID' });
      return;
   }
   if (userId !== undefined && (typeof userId !== 'string' || !UUID_REGEX.test(userId))) {
      res.status(400).json({ error: 'userId must be a valid UUID' });
      return;
   }
   if (autoRenew !== undefined && typeof autoRenew !== 'boolean') {
      res.status(400).json({ error: 'autoRenew must be a boolean' });
      return;
   }
   if (paymentMethod !== undefined && (typeof paymentMethod !== 'string' || paymentMethod.length > 100)) {
      res.status(400).json({ error: 'paymentMethod must be a string up to 100 characters' });
      return;
   }
   if (startTrial !== undefined && typeof startTrial !== 'boolean') {
      res.status(400).json({ error: 'startTrial must be a boolean' });
      return;
   }
   next();
}

export function validateUpdateSubscription(req: Request, res: Response, next: NextFunction): void {
   const { status } = req.body || {};
   const allowed = ['autoRenew', 'paymentMethod', 'cancelAtPeriodEnd', 'status'];
   const extra = Object.keys(req.body || {}).filter((k) => !allowed.includes(k));
   if (extra.length > 0) {
      res.status(400).json({ error: `Unexpected fields: ${extra.join(', ')}` });
      return;
   }
   if (Object.keys(req.body || {}).length === 0) {
      res.status(400).json({ error: 'At least one field must be provided for update' });
      return;
   }
   if (status !== undefined && !ALLOWED_STATUSES.includes(status)) {
      res.status(400).json({ error: `status must be one of: ${ALLOWED_STATUSES.join(', ')}` });
      return;
   }
   next();
}

export function validateChangePlan(req: Request, res: Response, next: NextFunction): void {
   const { planId } = req.body || {};
   if (!planId || typeof planId !== 'string' || !CUID_REGEX.test(planId)) {
      res.status(400).json({ error: 'planId must be a valid CUID' });
      return;
   }
   next();
}

export function validateCancelBody(req: Request, res: Response, next: NextFunction): void {
   const { cancelAtPeriodEnd } = req.body || {};
   if (cancelAtPeriodEnd !== undefined && typeof cancelAtPeriodEnd !== 'boolean') {
      res.status(400).json({ error: 'cancelAtPeriodEnd must be a boolean' });
      return;
   }
   next();
}

export function validateUserIdParam(req: Request, res: Response, next: NextFunction): void {
   const { userId } = req.params;
   if (!userId || !UUID_REGEX.test(userId)) {
      res.status(400).json({ error: 'userId must be a valid UUID' });
      return;
   }
   next();
}
