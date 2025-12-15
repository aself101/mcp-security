import { z } from 'zod';

export const echoSchema = z.object({
  message: z.string().min(1).max(1000).describe('Message to echo back'),
  uppercase: z.boolean().optional().default(false).describe('Convert to uppercase'),
  reverse: z.boolean().optional().default(false).describe('Reverse the message')
});

export type EchoArgs = z.infer<typeof echoSchema>;

export async function echoHandler(args: EchoArgs) {
  let { message } = args;
  const { uppercase, reverse } = args;

  if (uppercase) {
    message = message.toUpperCase();
  }

  if (reverse) {
    message = message.split('').reverse().join('');
  }

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        original: args.message,
        processed: message,
        transforms: {
          uppercase,
          reverse
        },
        timestamp: new Date().toISOString()
      }, null, 2)
    }]
  };
}
