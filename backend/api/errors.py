from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException


def error_response(status, message, fields=None):
    body = {"error": {"status": status, "message": message}}
    if fields:
        body["error"]["fields"] = fields
    return JSONResponse(status_code=status, content=body)


def add_error_handlers(app):
    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        return error_response(exc.status_code, str(exc.detail))

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        fields = []
        for error in exc.errors():
            location = ".".join(str(part) for part in error["loc"] if part != "body")
            fields.append({"field": location, "message": error["msg"]})
        return error_response(422, "invalid request", fields)

    @app.exception_handler(Exception)
    async def server_error(request, exc):
        return error_response(500, "internal server error")