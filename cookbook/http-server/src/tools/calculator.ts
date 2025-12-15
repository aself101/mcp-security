import { z } from 'zod';

export const calculatorSchema = z.object({
  operation: z.enum(['add', 'subtract', 'multiply', 'divide']).describe('Math operation to perform'),
  a: z.number().describe('First operand'),
  b: z.number().describe('Second operand')
});

export type CalculatorArgs = z.infer<typeof calculatorSchema>;

export async function calculatorHandler(args: CalculatorArgs) {
  const { operation, a, b } = args;

  let result: number;

  switch (operation) {
    case 'add':
      result = a + b;
      break;
    case 'subtract':
      result = a - b;
      break;
    case 'multiply':
      result = a * b;
      break;
    case 'divide':
      if (b === 0) {
        return {
          content: [{
            type: 'text' as const,
            text: JSON.stringify({ error: 'Division by zero' })
          }],
          isError: true
        };
      }
      result = a / b;
      break;
  }

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify({
        operation,
        a,
        b,
        result,
        expression: `${a} ${operationSymbol(operation)} ${b} = ${result}`
      }, null, 2)
    }]
  };
}

function operationSymbol(op: string): string {
  switch (op) {
    case 'add': return '+';
    case 'subtract': return '-';
    case 'multiply': return '*';
    case 'divide': return '/';
    default: return '?';
  }
}
