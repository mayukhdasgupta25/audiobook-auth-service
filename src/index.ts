import { startServer } from './app';
import { appLogger } from './utils/logger';

function formatStartupError(error: unknown): string {
   if (error instanceof Error) {
      return error.stack ?? error.message;
   }
   return String(error);
}

// Start the server
startServer().catch((error) => {
   appLogger.error({ err: error }, 'Failed to start server');
   // Fallback for early process exit before async log streams are flushed
   console.error('Failed to start server:', formatStartupError(error));
   process.exit(1);
});
