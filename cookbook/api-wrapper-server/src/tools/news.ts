/**
 * Tech News Headlines Tool
 * Wraps Hacker News Algolia API (free, no key required)
 * https://hn.algolia.com/api
 */

import { z } from 'zod';
import { fetchJson, sanitizeString } from '../utils/index.js';

const NEWS_API_BASE = 'https://hn.algolia.com/api/v1';

export const newsHeadlinesSchema = z.object({
  category: z.enum(['front_page', 'ask_hn', 'show_hn', 'jobs'])
    .default('front_page')
    .describe('News category: front_page, ask_hn (questions), show_hn (projects), jobs'),
  query: z.string()
    .max(100)
    .optional()
    .describe('Optional search query to filter stories'),
  limit: z.number()
    .int()
    .min(1)
    .max(10)
    .default(10)
    .describe('Maximum number of articles to return (max 10)'),
});

export type NewsHeadlinesArgs = z.infer<typeof newsHeadlinesSchema>;

interface HNSearchResult {
  hits: Array<{
    objectID: string;
    title: string;
    url: string | null;
    author: string;
    points: number;
    num_comments: number;
    created_at: string;
    story_text: string | null;
  }>;
  nbHits: number;
  page: number;
  nbPages: number;
}

function stripHtml(text: string | null): string {
  if (!text) return '';
  return text
    .replace(/<[^>]*>/g, '') // Remove HTML tags
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .trim();
}

function getCategoryTags(category: string): string {
  const tagMap: Record<string, string> = {
    'front_page': 'story',
    'ask_hn': 'ask_hn',
    'show_hn': 'show_hn',
    'jobs': 'job',
  };
  return tagMap[category] || 'story';
}

export async function newsHeadlines(args: NewsHeadlinesArgs) {
  const tags = getCategoryTags(args.category);
  const limit = Math.min(args.limit ?? 10, 10); // Enforce max 10

  let url: string;
  if (args.query) {
    const sanitizedQuery = sanitizeString(args.query, 100);
    url = `${NEWS_API_BASE}/search?` + new URLSearchParams({
      tags,
      query: sanitizedQuery,
      hitsPerPage: limit.toString(),
    });
  } else {
    // Use search_by_date for front page to get recent stories
    url = `${NEWS_API_BASE}/search_by_date?` + new URLSearchParams({
      tags,
      hitsPerPage: limit.toString(),
    });
  }

  const data = await fetchJson<HNSearchResult>(url, {
    timeout: 10000,
    maxResponseSize: 50 * 1024, // 50KB limit
  });

  const articles = data.hits.slice(0, limit).map(hit => ({
    id: hit.objectID,
    title: stripHtml(hit.title) || 'Untitled',
    url: hit.url || `https://news.ycombinator.com/item?id=${hit.objectID}`,
    author: hit.author,
    points: hit.points,
    comments: hit.num_comments,
    published: hit.created_at,
    excerpt: hit.story_text ? stripHtml(hit.story_text).slice(0, 200) + '...' : null,
  }));

  const result = {
    category: args.category,
    query: args.query || null,
    count: articles.length,
    totalAvailable: data.nbHits,
    articles,
  };

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify(result, null, 2),
    }],
  };
}
