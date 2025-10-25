import { config } from './config/env';
import { startServer } from './app';

console.log(config.DATABASE_URL)
// Start the server
startServer().catch((error) => {
   console.error('Failed to start server:', error);
   process.exit(1);
});
