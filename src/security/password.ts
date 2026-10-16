import argon2 from 'argon2';

// Parâmetros OWASP para Argon2id (m=64 MiB, t=3, p=4).
const OPTIONS: argon2.HashOptions & { raw?: false } = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4,
};

export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, OPTIONS);
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

// Hash fictício para igualar o tempo de resposta quando o usuário não existe
// (evita enumeração de e-mails por timing).
let dummyHash: Promise<string> | undefined;
export async function burnPasswordCheck(password: string): Promise<void> {
  dummyHash ??= hashPassword('dummy-password-for-timing-equalization');
  await verifyPassword(await dummyHash, password);
}

const COMMON = new Set([
  'password', 'senha', '123456', '12345678', '123456789', 'qwerty', 'admin', 'administrador',
  'condominio', 'sindico', 'mudar123', 'trocar123', 'brasil', 'imoveladmin',
]);

export const PASSWORD_MIN = 12;
export const PASSWORD_MAX = 128;

/** Retorna a lista de problemas da senha (vazia = senha aceita). */
export function passwordProblems(password: string, ctx: { email?: string; nome?: string } = {}): string[] {
  const problems: string[] = [];
  if (password.length < PASSWORD_MIN) problems.push(`A senha deve ter no mínimo ${PASSWORD_MIN} caracteres`);
  if (password.length > PASSWORD_MAX) problems.push(`A senha deve ter no máximo ${PASSWORD_MAX} caracteres`);
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(password)).length;
  if (classes < 3) problems.push('Use ao menos 3 entre: minúsculas, maiúsculas, números e símbolos');
  if (/(.)\1{3,}/.test(password)) problems.push('A senha não pode repetir o mesmo caractere 4 vezes seguidas');
  const lower = password.toLowerCase();
  for (const c of COMMON) {
    if (lower.includes(c)) {
      problems.push('A senha contém um termo muito comum');
      break;
    }
  }
  const local = ctx.email?.split('@')[0]?.toLowerCase();
  if (local && local.length >= 4 && lower.includes(local)) problems.push('A senha não pode conter seu e-mail');
  const parts = (ctx.nome ?? '').toLowerCase().split(/\s+/).filter((p) => p.length >= 4);
  if (parts.some((p) => lower.includes(p))) problems.push('A senha não pode conter seu nome');
  return problems;
}
