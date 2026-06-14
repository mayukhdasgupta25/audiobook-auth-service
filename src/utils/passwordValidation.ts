export function validateRegistrationPassword(
   password: string,
   confirmPassword: unknown,
): Record<string, string[]> {
   const details: Record<string, string[]> = {};
   const passwordErrors: string[] = [];

   if (password.length < 8) {
      passwordErrors.push('Password must be at least 8 characters');
   }

   if (!/[A-Z]/.test(password)) {
      passwordErrors.push('Password must contain at least one uppercase letter');
   }

   if (!/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
      passwordErrors.push('Password must contain at least one letter and one number');
   }

   if (!/[^A-Za-z0-9]/.test(password)) {
      passwordErrors.push('Password must contain at least one symbol');
   }

   if (passwordErrors.length > 0) {
      details['password'] = passwordErrors;
   }

   if (confirmPassword === undefined || confirmPassword === null || String(confirmPassword).length === 0) {
      details['confirmPassword'] = ['Confirm password is required'];
   } else if (password !== String(confirmPassword)) {
      details['confirmPassword'] = ['Password and confirm password do not match'];
   }

   return details;
}
