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

/**
 * True when the page's `<body onload>` calls a form's `submit()`, the signal
 * the SAML IdP's `autoSubmitForm` (src/saml.ts) emits and the README
 * documents: `<body onload="document.forms[0].submit()">`. Deliberately
 * narrow — a real browser submits a POST form only on a user action or a
 * script, and the only script this package's IdP ever runs is this one, so
 * matching it is enough without guessing at a broader heuristic. A `submit()`
 * call elsewhere on the page (a `<script>` block never wired to `onload`) is
 * not this signal and must not trigger a post.
 */
function hasAutoSubmit(html: string): boolean {
  const body = /<body[^>]*>/i.exec(html);
  if (!body) return false;
  const onload = /\bonload=["']([^"']*)["']/i.exec(body[0]);
  if (!onload) return false;
  return /\.submit\(\s*\)/.test(onload[1]);
}

/** Extracts a form's action and its hidden inputs, if the page is one. */
function parseForm(
  html: string,
  base: string,
): { action: string; fields: Record<string, string> } | null {
  if (!hasAutoSubmit(html)) return null;
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
  // Set only while a POST body is pending for the next hop — after
  // submitting a form, or after a 307/308 that itself followed one. Every
  // other 3xx (301, 302, 303) clears it, because a real browser repeats the
  // method and body only for 307 and 308; every other redirect becomes a GET.
  // Undefined here means the next hop is a plain GET, which is also what the
  // very first request always is.
  let pendingBody: string | undefined;

  for (let hop = 0; hop < MAX_REDIRECTS; hop++) {
    const res = await fetch(
      current,
      pendingBody === undefined
        ? { redirect: 'manual' }
        : {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body: pendingBody,
            // Manual, like every other fetch here. Left to its default the
            // POST would follow a redirect on its own, outside the hop cap,
            // and `finalUrl` below would still name the pre-redirect URL.
            redirect: 'manual',
          },
    );

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
      if (res.status !== 307 && res.status !== 308) {
        pendingBody = undefined;
      }
      continue;
    }

    const body = await res.text();
    const form = parseForm(body, current);
    if (form) {
      current = form.action;
      pendingBody = new URLSearchParams(form.fields).toString();
      continue;
    }

    return { finalUrl: current, status: res.status, body };
  }

  throw new Error(`Too many redirects starting from ${url}`);
}
