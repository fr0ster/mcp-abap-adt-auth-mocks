import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from '@jest/globals';
import * as mocks from '../index';

/** Every .ts file under src, so the constraint is checked against the code. */
function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(full);
    return entry.name.endsWith('.ts') ? [full] : [];
  });
}

describe('package skeleton', () => {
  it('exports something', () => {
    expect(Object.keys(mocks).length).toBeGreaterThan(0);
  });

  // UaaClient is exported so a consumer can type `redirectUris`, but
  // registering an extra URI *alongside* the default (rather than instead of
  // it) means retyping the literal unless the default itself is exported too.
  it('exports DEFAULT_REDIRECT_URI', () => {
    expect(mocks.DEFAULT_REDIRECT_URI).toBe('http://localhost:61001/callback');
  });

  // The package must never depend on the packages it exists to test: a mock
  // that knows our types will eventually agree with our mistakes. Both groups
  // are checked, not just runtime — a devDependency would let a test import our
  // types just as effectively.
  it('declares no @mcp-abap-adt dependency, in either group', () => {
    const pkg = require('../../package.json');
    const declared = [
      ...Object.keys(pkg.dependencies ?? {}),
      ...Object.keys(pkg.devDependencies ?? {}),
    ];
    expect(declared.filter((d) => d.startsWith('@mcp-abap-adt/'))).toEqual([]);
  });

  // package.json is the weaker half of the rule: a file can import a package
  // that was never declared, and the constraint breaks while the manifest stays
  // clean. So read the imports.
  it('imports nothing from @mcp-abap-adt in any source file', () => {
    const offenders = sourceFiles(join(__dirname, '..')).filter((file) =>
      /from\s+['"]@mcp-abap-adt\/|require\(\s*['"]@mcp-abap-adt\//.test(
        readFileSync(file, 'utf8'),
      ),
    );
    expect(offenders).toEqual([]);
  });
});
