/**
 * The shared core every mock is built on.
 *
 * Binds an ephemeral port, records every request it receives, and releases the
 * socket when closed. Routes are keyed `"METHOD /path"`; anything unmatched is
 * a journalled 404, because a test that mistypes a path should see that rather
 * than a hang.
 */

import * as http from 'node:http';
import type { AddressInfo } from 'node:net';

export interface RecordedRequest {
  method: string;
  path: string;
  query: Record<string, string>;
  headers: Record<string, string>;
  /** Parsed form body; empty for requests without one. */
  body: Record<string, string>;
  /** The body exactly as it arrived, for assertions parsing would lose. */
  raw: string;
}

export type RouteHandler = (
  req: RecordedRequest,
  res: http.ServerResponse,
) => void;

export type RouteTable = Record<string, RouteHandler>;

export interface MockHandle {
  url: string;
  port: number;
  /** Every request this mock received, oldest first. */
  requests: RecordedRequest[];
  close(): Promise<void>;
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    req.setEncoding('utf8');
    req.on('data', (chunk: string) => {
      data += chunk;
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

export async function startServer(
  routes: RouteTable,
  port = 0,
): Promise<MockHandle> {
  const requests: RecordedRequest[] = [];
  const sockets = new Set<import('node:net').Socket>();

  const server = http.createServer((req, res) => {
    void (async () => {
      const raw = await readBody(req);
      const url = new URL(req.url ?? '/', 'http://127.0.0.1');
      const query: Record<string, string> = {};
      url.searchParams.forEach((v, k) => {
        query[k] = v;
      });
      const body: Record<string, string> = {};
      if (
        raw &&
        /application\/x-www-form-urlencoded/.test(
          req.headers['content-type'] ?? '',
        )
      ) {
        new URLSearchParams(raw).forEach((v, k) => {
          body[k] = v;
        });
      }
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) {
        headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : (v ?? '');
      }

      const recorded: RecordedRequest = {
        method: req.method ?? 'GET',
        path: url.pathname,
        query,
        headers,
        body,
        raw,
      };
      requests.push(recorded);

      const handler = routes[`${recorded.method} ${recorded.path}`];
      if (!handler) {
        res.statusCode = 404;
        res.end('no such route');
        return;
      }
      // Awaited, not just called: an async handler's rejection is a separate
      // promise, and discarding it would slip straight past the catch below.
      await handler(recorded, res);
    })().catch((error: unknown) => {
      // This package exists to be fed malformed protocol input, so a throw
      // anywhere above is expected traffic, not an impossible state. Left
      // uncaught it becomes an unhandled rejection *and* a client that waits
      // for a response that will never come — a test that hangs instead of
      // failing, which is the worst outcome a test harness can produce.
      if (!res.headersSent) {
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
      }
      if (!res.writableEnded) {
        res.end(
          JSON.stringify({ error: 'mock_failure', detail: String(error) }),
        );
      }
    });
  });

  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  await new Promise<void>((resolve) =>
    server.listen(port, '127.0.0.1', resolve),
  );
  const bound = (server.address() as AddressInfo).port;

  return {
    url: `http://127.0.0.1:${bound}`,
    port: bound,
    requests,
    close: () =>
      new Promise<void>((resolve) => {
        for (const socket of sockets) socket.destroy();
        server.close(() => resolve());
      }),
  };
}
