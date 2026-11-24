import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

function resolveAppVersion(): string {
  const envVer = process.env.VITE_APP_VERSION?.trim();
  if (envVer) return envVer.startsWith('v') ? envVer : `v${envVer}`;
  try {
    const tag = execSync('git describe --tags --abbrev=0', { stdio: ['ignore', 'pipe', 'ignore'] })
      .toString()
      .trim();
    if (tag) return tag.startsWith('v') ? tag : `v${tag}`;
  } catch {
    // Fall back to package.json version when no git tags exist
  }
  const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf-8')) as {
    version?: string;
  };
  const v = pkg.version || '0.0.0';
  return v.startsWith('v') ? v : `v${v}`;
}

export default defineConfig({
  plugins: [react(), tailwindcss()],
  define: {
    __APP_VERSION__: JSON.stringify(resolveAppVersion()),
  },
});
