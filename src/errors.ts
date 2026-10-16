export class HttpError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
    public readonly details?: unknown,
  ) {
    super(message);
  }
}

export const unauthorized = (msg = 'Não autenticado') => new HttpError(401, 'NAO_AUTENTICADO', msg);
export const forbidden = (msg = 'Acesso negado') => new HttpError(403, 'ACESSO_NEGADO', msg);
export const notFound = (msg = 'Registro não encontrado') => new HttpError(404, 'NAO_ENCONTRADO', msg);
export const badRequest = (msg: string, details?: unknown) => new HttpError(400, 'REQUISICAO_INVALIDA', msg, details);
export const conflict = (msg: string) => new HttpError(409, 'CONFLITO', msg);
