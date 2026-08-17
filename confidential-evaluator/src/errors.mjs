export class HttpError extends Error {
  constructor(status, code, details = undefined) {
    super(code);
    this.name = "HttpError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export class ConfigurationError extends Error {
  constructor(message = "confidential evaluator configuration is invalid") {
    super(message);
    this.name = "ConfigurationError";
  }
}

export function invalidRequest() {
  throw new HttpError(400, "invalid_request");
}

export function unauthorized() {
  throw new HttpError(401, "unauthorized");
}

export function forbidden() {
  throw new HttpError(403, "forbidden");
}

export function serviceUnavailable() {
  throw new HttpError(503, "service_unavailable");
}
