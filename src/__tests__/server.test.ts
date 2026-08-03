import { describe, expect, it } from '@jest/globals';
import { startServer } from '../server';

describe('server core', () => {
  it('binds an ephemeral port and reports its own url', async () => {
    const s = await startServer({
      'GET /ping': (_req, res) => res.end('pong'),
    });
    try {
      expect(s.port).toBeGreaterThan(0);
      expect(s.url).toBe(`http://127.0.0.1:${s.port}`);
      const body = await (await fetch(`${s.url}/ping`)).text();
      expect(body).toBe('pong');
    } finally {
      await s.close();
    }
  });

  it('journals query, headers and form body of every request', async () => {
    const s = await startServer({ 'POST /echo': (_req, res) => res.end('ok') });
    try {
      await fetch(`${s.url}/echo?a=1`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=authorization_code&code=xyz',
      });
      expect(s.requests).toHaveLength(1);
      const r = s.requests[0];
      expect(r.method).toBe('POST');
      expect(r.path).toBe('/echo');
      expect(r.query.a).toBe('1');
      expect(r.body.grant_type).toBe('authorization_code');
      expect(r.body.code).toBe('xyz');
    } finally {
      await s.close();
    }
  });

  it('answers 404 for an unrouted path and still journals it', async () => {
    const s = await startServer({});
    try {
      const res = await fetch(`${s.url}/nope`);
      expect(res.status).toBe(404);
      expect(s.requests[0].path).toBe('/nope');
    } finally {
      await s.close();
    }
  });

  it('releases the port when closed', async () => {
    const s = await startServer({});
    const port = s.port;
    await s.close();
    // Binding the same port must now succeed.
    const again = await startServer({}, port);
    expect(again.port).toBe(port);
    await again.close();
  });

  // This package exists to be fed malformed protocol input, so a throw inside a
  // handler is expected traffic. Uncaught it becomes an unhandled rejection and
  // a client waiting for a response that never comes — a hanging test instead
  // of a failing one, which is the worst thing a harness can do.
  it('answers 500 when a route handler throws, rather than hanging', async () => {
    const s = await startServer({
      'GET /boom': () => {
        throw new Error('handler exploded');
      },
      'GET /boom-async': async () => {
        throw new Error('async handler exploded');
      },
    });
    try {
      const sync = await fetch(`${s.url}/boom`);
      expect(sync.status).toBe(500);
      const syncBody = (await sync.json()) as { error: string };
      expect(syncBody.error).toBe('mock_failure');

      // The async case is the one that slips through a bare `void (async …)()`.
      const asynchronous = await fetch(`${s.url}/boom-async`);
      expect(asynchronous.status).toBe(500);
    } finally {
      await s.close();
    }
  }, 10000);
});
