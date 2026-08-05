/**
 * A browser, reduced to what an authorization flow needs from one.
 *
 * It follows redirects and submits auto-submitting forms — the two things a
 * real browser does during an OAuth redirect or a SAML HTTP-POST binding. It is
 * wired in through `openUrl`, so the code under test runs its own orchestration
 * and only the browser is replaced.
 */

const MAX_REDIRECTS = 10;

export interface VisitResult {
  finalUrl: string;
  status: number;
  body: string;
}

/**
 * Reverses HTML attribute escaping.
 *
 * A real browser does this, so a browser that does not is not testing the
 * client — it is testing a value the client would never have seen. `&amp;`
 * must be last: decoding it first would turn `&amp;lt;` into `<`.
 */
function decodeEntities(value: string): string {
  return value
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#0*39;|&#x0*27;/gi, "'")
    .replace(/&#(\d+);/g, (_m, d) => String.fromCodePoint(Number(d)))
    .replace(/&#x([0-9a-f]+);/gi, (_m, h) =>
      String.fromCodePoint(Number.parseInt(h, 16)),
    )
    .replace(/&amp;/g, '&');
}

/** Extracts a form's action and its hidden inputs, if the page is one. */
function parseForm(
  html: string,
  base: string,
): { action: string; fields: Record<string, string> } | null {
  const form = /<form[^>]*method=["']post["'][^>]*>([\s\S]*?)<\/form>/i.exec(
    html,
  );
  if (!form) return null;
  const actionMatch = /action=["']([^"']*)["']/i.exec(form[0]);
  const action = new URL(
    decodeEntities(actionMatch?.[1] ?? ''),
    base,
  ).toString();
  const fields: Record<string, string> = {};
  const input = /<input[^>]*>/gi;
  let m: RegExpExecArray | null = input.exec(form[1]);
  while (m) {
    const name = /name=["']([^"']+)["']/i.exec(m[0])?.[1];
    const value = /value=["']([^"']*)["']/i.exec(m[0])?.[1] ?? '';
    if (name) fields[name] = decodeEntities(value);
    m = input.exec(form[1]);
  }
  return { action, fields };
}

export async function visit(url: string): Promise<VisitResult> {
  let current = url;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const res = await fetch(current, { redirect: 'manual' });

    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get('location');
      if (!location) {
        return {
          finalUrl: current,
          status: res.status,
          body: await res.text(),
        };
      }
      current = new URL(location, current).toString();
      continue;
    }

    const body = await res.text();
    const form = parseForm(body, current);
    if (form) {
      const posted = await fetch(form.action, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(form.fields).toString(),
      });
      return {
        finalUrl: form.action,
        status: posted.status,
        body: await posted.text(),
      };
    }

    return { finalUrl: current, status: res.status, body };
  }

  throw new Error(`Too many redirects starting from ${url}`);
}
