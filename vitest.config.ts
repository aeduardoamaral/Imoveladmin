import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 60_000,
    globalSetup: ['tests/global-setup.ts'],
    env: {
      NODE_ENV: 'test',
      DATABASE_URL: process.env.TEST_DATABASE_URL ?? 'postgres://imovel_app:app_dev_pw@localhost:5432/imoveladmin_test',
      DATABASE_OWNER_URL: process.env.TEST_DATABASE_OWNER_URL ?? 'postgres://imovel_owner:owner_dev_pw@localhost:5432/imoveladmin_test',
      APP_DB_ROLE: 'imovel_app',
      JWT_SECRET: 'test-secret-test-secret-test-secret-test-secret-0123456789',
      MFA_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString('base64'),
      CORS_ORIGINS: 'http://localhost:5173',
      APP_PUBLIC_URL: 'http://localhost:5173',
    },
  },
});
