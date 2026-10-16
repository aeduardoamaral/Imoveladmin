import { parseArgs } from 'node:util';
import { audit } from '../audit.js';
import { issueInvitation } from '../auth/service.js';
import { closePool, withTx } from '../db.js';
import { zEmail } from '../http.js';

/**
 * Cria um usuário MASTER. Não existe rota pública para isso: somente quem tem
 * acesso ao servidor e às credenciais do banco consegue criar o primeiro Master.
 * O comando imprime um link de convite de uso único (72h) para definir a senha;
 * no primeiro login o cadastro do autenticador (MFA) é obrigatório.
 *
 *   npm run master:create -- --email voce@empresa.com.br --nome "Seu Nome"
 */
const { values } = parseArgs({ options: { email: { type: 'string' }, nome: { type: 'string' } } });
const email = zEmail.parse(values.email);
const nome = (values.nome ?? '').trim();
if (nome.length < 2) throw new Error('Informe --nome');

const convite = await withTx({ role: 'system' }, async (tx) => {
  const { rows } = await tx.query(
    `INSERT INTO users (nome, email, role, status) VALUES ($1, $2, 'MASTER', 'PENDENTE') RETURNING id`,
    [nome, email],
  );
  const inv = await issueInvitation(tx, rows[0].id, null);
  await audit(tx, null, { action: 'MASTER_CRIADO_VIA_CLI', entity: 'user', entityId: rows[0].id, details: { email } });
  return inv;
});
await closePool();

console.log(`\nUsuário MASTER criado: ${email}`);
console.log(`Link de convite (uso único, expira em ${convite.expiraEm.toISOString()}):\n\n  ${convite.url}\n`);
console.log('Guarde este link com segurança: ele permite definir a senha da conta Master.');
