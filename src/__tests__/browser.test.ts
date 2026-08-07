import { describe, expect, it } from '@jest/globals';
import { visit } from '../browser';
import { startServer } from '../server';

describe('visit', () => {
  it('follows a redirect chain to its end', async () => {
    const s = await startServer({
      'GET /a': (_r, res) => {
        res.statusCode = 302;
        res.setHeader('Location', '/b');
        res.end();
      },
      'GET /b': (_r, res) => res.end('arrived'),
    });
    try {
      const result = await visit(`${s.url}/a`);
      expect(result.body).toBe('arrived');
      expect(result.finalUrl).toBe(`${s.url}/b`);
    } finally {
      await s.close();
    }
  });

  it('submits an auto-submitting form, carrying every field', async () => {
    let received: Record<string, string> = {};
    const s = await startServer({
      'GET /idp': (_r, res) => {
        res.setHeader('Content-Type', 'text/html');
        res.end(
          `<html><body onload="document.forms[0].submit()">
           <form method="post" action="/acs">
             <input type="hidden" name="SAMLResponse" value="PHNhbWw+"/>
             <input type="hidden" name="RelayState" value="rs-123"/>
           </form></body></html>`,
        );
      },
      'POST /acs': (req, res) => {
        received = req.body;
        res.end('consumed');
      },
    });
    try {
      const result = await visit(`${s.url}/idp`);
      expect(received.SAMLResponse).toBe('PHNhbWw+');
      expect(received.RelayState).toBe('rs-123');
      expect(result.body).toBe('consumed');
    } finally {
      await s.close();
    }
  });

  // A real browser decodes attribute entities before submitting. One that does
  // not would hand the client a value no real flow could produce, and a bug in
  // the client's handling of & or a quote would never be reached.
  it('decodes HTML entities in form values and in the action', async () => {
    let received: Record<string, string> = {};
    let query: Record<string, string> = {};
    const s = await startServer({
      'GET /idp': (_r, res) => {
        res.setHeader('Content-Type', 'text/html');
        res.end(
          `<html><body onload="document.forms[0].submit()">
           <form method="post" action="/acs?a=1&amp;b=2">
             <input type="hidden" name="RelayState" value="a&amp;b&quot;c&lt;d"/>
           </form></body></html>`,
        );
      },
      'POST /acs': (req, res) => {
        received = req.body;
        query = req.query;
        res.end('ok');
      },
    });
    try {
      await visit(`${s.url}/idp`);
      expect(received.RelayState).toBe('a&b"c<d');
      // Decoded once, not twice: the action carried one & and still does.
      expect(query).toEqual({ a: '1', b: '2' });
    } finally {
      await s.close();
    }
  });

  // The ordering inside decodeEntities is a rule, so it needs a case that
  // breaks when the order changes. `&amp;lt;` is text the server chose to send:
  // decoding `&amp;` first turns it into `<`, a string the server never sent.
  // Nothing above distinguishes the two orders — none of those values is
  // double-escaped.
  it('decodes each entity once, so &amp;lt; stays literal text', async () => {
    let received: Record<string, string> = {};
    const s = await startServer({
      'GET /idp': (_r, res) => {
        res.setHeader('Content-Type', 'text/html');
        res.end(
          `<html><body onload="document.forms[0].submit()">
           <form method="post" action="/acs">
             <input type="hidden" name="RelayState" value="&amp;lt;tag&amp;gt;"/>
           </form></body></html>`,
        );
      },
      'POST /acs': (req, res) => {
        received = req.body;
        res.end('ok');
      },
    });
    try {
      await visit(`${s.url}/idp`);
      expect(received.RelayState).toBe('&lt;tag&gt;');
    } finally {
      await s.close();
    }
  });

  // Three rules the code performs that nothing above would notice losing.
  it('decodes numeric character references, decimal and hex', async () => {
    let received: Record<string, string> = {};
    const s = await startServer({
      'GET /idp': (_r, res) => {
        res.setHeader('Content-Type', 'text/html');
        res.end(
          `<html><body onload="document.forms[0].submit()">
           <form method="post" action="/acs">
             <input type="hidden" name="RelayState" value="&#65;&#x42;&#39;&#x27;"/>
           </form></body></html>`,
        );
      },
      'POST /acs': (req, res) => {
        received = req.body;
        res.end('ok');
      },
    });
    try {
      await visit(`${s.url}/idp`);
      expect(received.RelayState).toBe("AB''");
    } finally {
      await s.close();
    }
  });

  it('stops at a 3xx that carries no Location', async () => {
    const s = await startServer({
      'GET /dead-end': (_r, res) => {
        res.statusCode = 302;
        res.end('nowhere to go');
      },
    });
    try {
      const result = await visit(`${s.url}/dead-end`);
      expect(result.status).toBe(302);
      expect(result.finalUrl).toBe(`${s.url}/dead-end`);
      expect(result.body).toBe('nowhere to go');
    } finally {
      await s.close();
    }
  });

  // An ACS commonly redirects once it has consumed the assertion. A browser
  // follows; so must this one, and finalUrl must name where it ended up rather
  // than the form's action.
  it('keeps following after the form POST, and reports where it landed', async () => {
    const s = await startServer({
      'GET /idp': (_r, res) => {
        res.setHeader('Content-Type', 'text/html');
        res.end(
          `<html><body onload="document.forms[0].submit()">
           <form method="post" action="/acs">
             <input type="hidden" name="SAMLResponse" value="PHNhbWw+"/>
           </form></body></html>`,
        );
      },
      'POST /acs': (_r, res) => {
        res.statusCode = 303;
        res.setHeader('Location', '/done');
        res.end();
      },
      'GET /done': (_r, res) => res.end('landed'),
    });
    try {
      const result = await visit(`${s.url}/idp`);
      expect(result.body).toBe('landed');
      expect(result.finalUrl).toBe(`${s.url}/done`);
      expect(result.status).toBe(200);
    } finally {
      await s.close();
    }
  });

  // RFC 7231 §6.4: only 307 and 308 tell a real browser to repeat the same
  // method and body; every other redirect (301, 302, 303) becomes a GET. Both
  // targets register both methods so the assertion is on which one actually
  // arrived, not on a 404 that a wrong method would produce incidentally.
  it('repeats the same POST body on a 307 after the form POST', async () => {
    const s = await startServer({
      'GET /idp': (_r, res) => {
        res.setHeader('Content-Type', 'text/html');
        res.end(
          `<html><body onload="document.forms[0].submit()">
           <form method="post" action="/acs">
             <input type="hidden" name="SAMLResponse" value="PHNhbWw+"/>
           </form></body></html>`,
        );
      },
      'POST /acs': (_r, res) => {
        res.statusCode = 307;
        res.setHeader('Location', '/acs2');
        res.end();
      },
      'GET /acs2': (_r, res) => res.end('got-get'),
      'POST /acs2': (req, res) => res.end(`got-post:${req.body.SAMLResponse}`),
    });
    try {
      const result = await visit(`${s.url}/idp`);
      expect(result.body).toBe('got-post:PHNhbWw+');
      expect(result.finalUrl).toBe(`${s.url}/acs2`);
      expect(result.status).toBe(200);
    } finally {
      await s.close();
    }
  });

  it('follows a 303 after the form POST with a GET, not a repeated POST', async () => {
    const s = await startServer({
      'GET /idp': (_r, res) => {
        res.setHeader('Content-Type', 'text/html');
        res.end(
          `<html><body onload="document.forms[0].submit()">
           <form method="post" action="/acs">
             <input type="hidden" name="SAMLResponse" value="PHNhbWw+"/>
           </form></body></html>`,
        );
      },
      'POST /acs': (_r, res) => {
        res.statusCode = 303;
        res.setHeader('Location', '/done');
        res.end();
      },
      'GET /done': (_r, res) => res.end('got-get'),
      'POST /done': (_r, res) => res.end('got-post'),
    });
    try {
      const result = await visit(`${s.url}/idp`);
      expect(result.body).toBe('got-get');
      expect(result.finalUrl).toBe(`${s.url}/done`);
      expect(result.status).toBe(200);
    } finally {
      await s.close();
    }
  });

  it('stops rather than looping forever on a redirect cycle', async () => {
    const s = await startServer({
      'GET /loop': (_r, res) => {
        res.statusCode = 302;
        res.setHeader('Location', '/loop');
        res.end();
      },
    });
    try {
      await expect(visit(`${s.url}/loop`)).rejects.toThrow(
        /too many redirects/i,
      );
    } finally {
      await s.close();
    }
  });
});
