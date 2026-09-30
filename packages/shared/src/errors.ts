/** 带错误码的异常，模拟 authenticator 侧 DOMException 风格的错误。 */
export class CodedError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'CodedError';
  }
}

export function fail(code: string, message: string): never {
  throw new CodedError(code, message);
}
