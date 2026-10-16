import { describe, expect, it } from 'vitest';
import { decrypt, encrypt } from '../src/security/crypto.js';
import { isValidCnpj, isValidCpf } from '../src/security/documents.js';
import { passwordProblems } from '../src/security/password.js';
import { codeAt, verifyTotp } from '../src/security/totp.js';

describe('documentos', () => {
  it('valida CPF', () => {
    expect(isValidCpf('529.982.247-25')).toBe(true);
    expect(isValidCpf('529.982.247-24')).toBe(false);
    expect(isValidCpf('111.111.111-11')).toBe(false);
  });
  it('valida CNPJ numérico e alfanumérico', () => {
    expect(isValidCnpj('11.222.333/0001-81')).toBe(true);
    expect(isValidCnpj('11.222.333/0001-80')).toBe(false);
    expect(isValidCnpj('12.ABC.345/01DE-35')).toBe(true); // exemplo oficial da Receita Federal
    expect(isValidCnpj('12.ABC.345/01DE-36')).toBe(false);
    expect(isValidCnpj('00.000.000/0000-00')).toBe(false);
  });
});

describe('TOTP (RFC 6238)', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // "12345678901234567890"
  it('gera o vetor de teste oficial', () => {
    expect(codeAt(secret, Math.floor(59 / 30))).toBe('287082');
    expect(codeAt(secret, Math.floor(1111111109 / 30))).toBe('081804');
  });
  it('bloqueia reuso do mesmo código', () => {
    const now = 1111111109_000;
    const code = codeAt(secret, Math.floor(now / 30000));
    const step = verifyTotp(secret, code, null, now);
    expect(step).not.toBeNull();
    expect(verifyTotp(secret, code, step, now)).toBeNull();
  });
});

describe('criptografia', () => {
  it('cifra e detecta adulteração ou troca de contexto', () => {
    const c = encrypt('segredo', 'user:1');
    expect(decrypt(c, 'user:1')).toBe('segredo');
    expect(() => decrypt(c, 'user:2')).toThrow();
    const parts = c.split('.');
    parts[3] = Buffer.from('xxxxxxx').toString('base64url');
    expect(() => decrypt(parts.join('.'), 'user:1')).toThrow();
  });
});

describe('política de senha', () => {
  it('rejeita senhas fracas', () => {
    expect(passwordProblems('curta')).not.toHaveLength(0);
    expect(passwordProblems('somenteletrasminusculas')).not.toHaveLength(0);
    expect(passwordProblems('Senha123456!')).not.toHaveLength(0); // termo comum
    expect(passwordProblems('Joaquim#2026xyz', { nome: 'Joaquim Silva' })).not.toHaveLength(0);
    expect(passwordProblems('Cofre#Forte-2026!')).toHaveLength(0);
  });
});
