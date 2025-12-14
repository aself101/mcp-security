/**
 * Utility exports for database server
 */

export {
  getDatabase,
  closeDatabase,
  type User,
  type Order,
  type OrderItem,
} from './database.js';

export {
  formatZodError,
  withZodErrorHandling,
  type FormattedError,
} from './zod-errors.js';
