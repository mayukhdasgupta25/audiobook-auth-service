import { startServer } from './app';
import { appLogger } from './utils/logger';

// Start the server
startServer().catch((error) => {
   appLogger.error({ err: error }, 'Failed to start server');
   process.exit(1);
});
