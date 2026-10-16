// Validação de CPF e CNPJ (incluindo o CNPJ alfanumérico - IN RFB 2.229/2024,
// em vigor a partir de julho/2026).

export function onlyDigits(v: string): string {
  return v.replace(/\D/g, '');
}

export function normalizeCnpj(v: string): string {
  return v.toUpperCase().replace(/[^0-9A-Z]/g, '');
}

export function isValidCpf(raw: string): boolean {
  const cpf = onlyDigits(raw);
  if (cpf.length !== 11 || /^(\d)\1{10}$/.test(cpf)) return false;
  const digits = cpf.split('').map(Number);
  for (const len of [9, 10]) {
    let sum = 0;
    for (let i = 0; i < len; i++) sum += digits[i]! * (len + 1 - i);
    const dv = ((sum * 10) % 11) % 10;
    if (dv !== digits[len]) return false;
  }
  return true;
}

export function isValidCnpj(raw: string): boolean {
  const cnpj = normalizeCnpj(raw);
  if (!/^[0-9A-Z]{12}[0-9]{2}$/.test(cnpj)) return false;
  if (/^(\d)\1{13}$/.test(cnpj)) return false;
  // Valor de cada caractere = código ASCII - 48 (dígitos 0-9, letras A=17 ... Z=42)
  const values = cnpj.split('').map((c) => c.charCodeAt(0) - 48);
  const calc = (len: number) => {
    const weights = len === 12 ? [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2] : [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    const sum = weights.reduce((acc, w, i) => acc + w * values[i]!, 0);
    const r = sum % 11;
    return r < 2 ? 0 : 11 - r;
  };
  return calc(12) === values[12] && calc(13) === values[13];
}
