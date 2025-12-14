/**
 * Input Validation Example
 *
 * Demonstrates Zod schema validation for database inputs.
 * Validation happens BEFORE any database interaction.
 */

import { z } from 'zod';

/**
 * Define strict schemas for all inputs
 *
 * Zod validates types, lengths, patterns, and custom constraints.
 * Invalid data is rejected before it ever touches the database.
 */
const createUserSchema = z.object({
  name: z
    .string()
    .min(1, 'Name is required')
    .max(100, 'Name must be 100 characters or less')
    .regex(/^[a-zA-Z\s'-]+$/, 'Name contains invalid characters'),

  email: z
    .string()
    .email('Invalid email format')
    .max(255, 'Email must be 255 characters or less'),

  age: z
    .number()
    .int('Age must be a whole number')
    .min(0, 'Age cannot be negative')
    .max(150, 'Age must be realistic'),

  department: z
    .enum(['Engineering', 'Sales', 'Marketing', 'HR', 'Finance'], {
      errorMap: () => ({
        message: 'Department must be one of: Engineering, Sales, Marketing, HR, Finance',
      }),
    }),
});

type CreateUserInput = z.infer<typeof createUserSchema>;

/**
 * Validate and create user
 */
function createUser(input: unknown): { success: boolean; data?: CreateUserInput; errors?: string[] } {
  const result = createUserSchema.safeParse(input);

  if (!result.success) {
    return {
      success: false,
      errors: result.error.errors.map((e) => `${e.path.join('.')}: ${e.message}`),
    };
  }

  // Input is now type-safe and validated
  const user = result.data;
  console.log(`Creating user: ${user.name} (${user.email})`);

  return { success: true, data: user };
}

// Test valid input
console.log('Valid input:');
console.log(
  createUser({
    name: "Alice O'Brien",
    email: 'alice@example.com',
    age: 30,
    department: 'Engineering',
  })
);

// Test invalid email
console.log('\nInvalid email:');
console.log(
  createUser({
    name: 'Bob',
    email: 'not-an-email',
    age: 25,
    department: 'Sales',
  })
);

// Test SQL injection in name (blocked by regex)
console.log('\nSQL injection attempt in name:');
console.log(
  createUser({
    name: "'; DROP TABLE users; --",
    email: 'hacker@evil.com',
    age: 25,
    department: 'Engineering',
  })
);

// Test invalid department
console.log('\nInvalid department:');
console.log(
  createUser({
    name: 'Carol',
    email: 'carol@example.com',
    age: 28,
    department: 'InvalidDept',
  })
);

// Test numeric overflow
console.log('\nNumeric overflow attempt:');
console.log(
  createUser({
    name: 'Dave',
    email: 'dave@example.com',
    age: 999999999999,
    department: 'HR',
  })
);
