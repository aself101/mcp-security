import { z } from 'zod';

export const listUsersSchema = z.object({
  limit: z.number().min(1).max(100).optional().default(10).describe('Maximum users to return'),
  offset: z.number().min(0).optional().default(0).describe('Pagination offset'),
  role: z.enum(['admin', 'user', 'guest']).optional().describe('Filter by role')
});

export type ListUsersArgs = z.infer<typeof listUsersSchema>;

// Mock user database
const mockUsers = [
  { id: 1, name: 'Alice Admin', email: 'alice@example.com', role: 'admin', createdAt: '2024-01-01' },
  { id: 2, name: 'Bob User', email: 'bob@example.com', role: 'user', createdAt: '2024-02-15' },
  { id: 3, name: 'Carol User', email: 'carol@example.com', role: 'user', createdAt: '2024-03-10' },
  { id: 4, name: 'Dave Guest', email: 'dave@example.com', role: 'guest', createdAt: '2024-04-20' },
  { id: 5, name: 'Eve Admin', email: 'eve@example.com', role: 'admin', createdAt: '2024-05-05' }
];

export async function listUsersHandler(args: ListUsersArgs) {
  const { limit, offset, role } = args;

  let users = [...mockUsers];

  // Filter by role if specified
  if (role) {
    users = users.filter(u => u.role === role);
  }

  // Apply pagination
  const total = users.length;
  const paginated = users.slice(offset, offset + limit);

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        users: paginated,
        pagination: {
          total,
          limit,
          offset,
          hasMore: offset + limit < total
        }
      }, null, 2)
    }]
  };
}
