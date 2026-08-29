#!/usr/bin/env python3
"""Attestor 3.0 precision source-to-sink security catalog.

This pack deliberately counts *semantic flow specifications*, not copies of a
regex with renamed identifiers.  A specification is the Cartesian relation of
one concrete framework input channel and one concrete dangerous API operation.
The checked-in dimensions are 25 ecosystems x 12 input channels x 50 sinks,
giving exactly 15,000 independently addressable rules.

Rules are materialized lazily.  Scanning never loops over 15,000 rules: it
activates framework profiles using import markers, indexes their 12 sources,
and evaluates only the 50 sinks for the file's language.  Direct flows and
bounded local-variable flows are supported; comments, strings, recognized
sanitizers, SQL parameterization, reassignment, and explicit suppressions are
negative guards.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterator, Sequence


PACK = "precision-flow-2.3"
MAX_FLOW_STATEMENTS = 6
KEY_PATTERN = r'(?:["\'][^"\'\r\n]{1,80}["\']|\$?[A-Za-z_][\w$]*)'


@dataclass(frozen=True)
class SourceDef:
    sid: str
    label: str
    template: str
    pattern: str
    example: str


@dataclass(frozen=True)
class Profile:
    ecosystem: str
    language: str
    path_hint: str
    marker: str
    reference: str
    sources: tuple[SourceDef, ...]


@dataclass(frozen=True)
class Family:
    key: str
    label: str
    category: str
    cwe: str
    owasp: str
    severity: str
    confidence: float
    asvs: tuple[str, ...]
    cwe_top25_2025_rank: int | None
    description: str
    remediation: str
    sanitizers: tuple[str, ...]


@dataclass(frozen=True)
class SinkDef:
    family: str
    sid: str
    label: str
    template: str
    pattern: str
    anchor: str
    example: str

    @lru_cache(maxsize=None)
    def regex(self) -> re.Pattern[str]:
        return re.compile(self.pattern)


@dataclass(frozen=True)
class FlowRule:
    rid: str
    fingerprint: str
    language: str
    ecosystem: str
    source_channel: str
    source_signature: str
    sink_operation: str
    sink_signature: str
    severity: str
    confidence: float
    category: str
    cwe: str
    cwe_top25_2025_rank: int | None
    owasp: str
    asvs: tuple[str, ...]
    description: str
    remediation: str
    references: tuple[str, ...]
    pack: str = PACK

    # Compatibility aliases used by Attestor's earlier rule/report surfaces.
    @property
    def message(self) -> str:
        return self.description

    @property
    def fix(self) -> str:
        return self.remediation


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    language: str
    rule: str
    severity: str
    message: str
    fix: str
    category: str
    cwe: str
    owasp: str
    confidence: float
    evidence: str
    ecosystem: str
    source_channel: str
    sink_operation: str
    fingerprint: str
    asvs: tuple[str, ...]
    cwe_top25_2025_rank: int | None
    pack: str = PACK


SOURCE_CHANNELS = (
    ("query", "query-string parameter"),
    ("path", "route/path parameter"),
    ("header", "HTTP request header"),
    ("cookie", "request cookie"),
    ("form", "form field"),
    ("body", "raw request body"),
    ("json", "JSON request field"),
    ("file", "uploaded file content"),
    ("filename", "client-supplied upload filename"),
    ("route", "request URL or route value"),
    ("host", "request Host/authority value"),
    ("auth", "client-supplied authentication material"),
)


def _literal_pattern(value: str) -> str:
    """Escape a signature template while allowing ordinary whitespace drift."""
    return re.escape(value).replace(r"\ ", r"\s*").replace(r"\	", r"\s*")


def _source_pattern(template: str, module: str = "") -> str:
    """Compile one source template, optionally allowing a module qualifier.

    The leading `(?<![\\w.$])` stops `myrequest.args.get(...)` and
    `self.request.args.get(...)` matching a `request.args.get` template, which
    is right. But it forbids *any* preceding dot, and that also excludes the
    module-qualified spelling of the very same source:

        from flask import request     ->  request.args.get("x")        found
        import flask                  ->  flask.request.args.get("x")  missed

    Both are the identical vulnerability. The profile marker accepts either
    import form, so the profile activated and then nothing was detected --
    measured as 1 finding against 0 on the same flaw.

    So exactly one qualifier is permitted, and only the framework's own module
    name. Anything else stays blocked, because `something_else.request.args`
    is not evidence that Flask's request object is involved.
    """
    chunks = template.split("{key}")
    pattern = KEY_PATTERN.join(_literal_pattern(chunk) for chunk in chunks)
    if template and (template[0].isalnum() or template[0] in "_$"):
        qualifier = r"(?:%s\s*\.\s*)?" % re.escape(module) if module else ""
        pattern = r"(?<![\w.$])" + qualifier + pattern
    if template and (template[-1].isalnum() or template[-1] in "_$"):
        pattern += r"(?![\w$])"
    return pattern


def _profile(ecosystem: str, language: str, path_hint: str, marker: str,
             reference: str, templates: tuple[str, ...]) -> Profile:
    if len(templates) != len(SOURCE_CHANNELS):
        raise ValueError("%s must define exactly 12 source channels" % ecosystem)
    # "python-flask" -> "flask". The qualifier a caller may legitimately put
    # in front of this framework's sources is the framework's own module.
    module = ecosystem.rsplit("-", 1)[-1]
    sources = []
    for (sid, label), template in zip(SOURCE_CHANNELS, templates):
        sources.append(SourceDef(
            sid=sid,
            label=label,
            template=template,
            pattern=_source_pattern(template, module),
            example=template.replace("{key}", '"attestor_input"'),
        ))
    return Profile(ecosystem, language, path_hint, marker, reference, tuple(sources))


PROFILES: tuple[Profile, ...] = (
    _profile("python-django", "python", "views.py",
        r"(?m)^\s*(?:from|import)\s+django\b", "https://docs.djangoproject.com/en/5.2/ref/request-response/", (
        "request.GET.get({key})", "request.resolver_match.kwargs.get({key})",
        "request.headers.get({key})", "request.COOKIES.get({key})",
        "request.POST.get({key})", "request.body", "json.loads(request.body).get({key})",
        "request.FILES.get({key}).read()", "request.FILES.get({key}).name",
        "request.get_full_path()", "request.META.get(HTTP_HOST)",
        "request.META.get(HTTP_AUTHORIZATION)",
    )),
    _profile("python-flask", "python", "app.py",
        r"(?m)^\s*(?:from|import)\s+flask\b", "https://flask.palletsprojects.com/en/stable/api/#incoming-request-data", (
        "request.args.get({key})", "request.view_args.get({key})", "request.headers.get({key})",
        "request.cookies.get({key})", "request.form.get({key})", "request.get_data()",
        "request.get_json().get({key})", "request.files.get({key}).read()",
        "request.files.get({key}).filename", "request.full_path", "request.host",
        "request.headers.get(AUTHORIZATION)",
    )),
    _profile("python-fastapi", "python", "main.py",
        r"(?m)^\s*(?:from|import)\s+fastapi\b", "https://fastapi.tiangolo.com/tutorial/body/", (
        "request.query_params.get({key})", "request.path_params.get({key})",
        "request.headers.get({key})", "request.cookies.get({key})",
        "(await request.form()).get({key})", "await request.body()",
        "(await request.json()).get({key})", "await upload.read()",
        "upload.filename", "request.url.path", "request.headers.get(HOST)",
        "request.headers.get(AUTHORIZATION)",
    )),
    _profile("python-aiohttp", "python", "handlers.py",
        r"(?m)^\s*(?:from|import)\s+aiohttp\b", "https://docs.aiohttp.org/en/stable/web_reference.html#aiohttp.web.Request", (
        "request.query.get({key})", "request.match_info.get({key})", "request.headers.get({key})",
        "request.cookies.get({key})", "(await request.post()).get({key})", "await request.read()",
        "(await request.json()).get({key})", "(await request.post()).get({key}).file.read()",
        "(await request.post()).get({key}).filename", "request.rel_url.raw_path", "request.headers.get(HOST)",
        "request.headers.get(AUTHORIZATION)",
    )),
    _profile("python-tornado", "python", "handler.py",
        r"(?m)^\s*(?:from|import)\s+tornado\b", "https://www.tornadoweb.org/en/stable/web.html#tornado.web.RequestHandler", (
        "self.get_query_argument({key})", "self.path_kwargs.get({key})",
        "self.request.headers.get({key})", "self.get_cookie({key})",
        "self.get_body_argument({key})", "self.request.body",
        "json.loads(self.request.body).get({key})", "self.request.files.get({key})[0].body",
        "self.request.files.get({key})[0].filename", "self.request.path", "self.request.headers.get(HOST)",
        "self.request.headers.get(AUTHORIZATION)",
    )),
    _profile("javascript-express", "javascript", "app.js",
        r"(?m)^\s*(?:import\b.*?[\"']express[\"']|(?:const|let|var)\s+\w+\s*=\s*require\([\"']express[\"']\))",
        "https://expressjs.com/en/4x/api.html#req", (
        "req.query[{key}]", "req.params[{key}]", "req.get({key})", "req.cookies[{key}]",
        "req.body[{key}]", "req.rawBody", "req.body.data[{key}]", "req.files[{key}].data",
        "req.files[{key}].name", "req.originalUrl", "req.get(HOST)", "req.get(AUTHORIZATION)",
    )),
    _profile("javascript-koa", "javascript", "app.js",
        r"(?m)^\s*(?:import\b.*?[\"']koa[\"']|(?:const|let|var)\s+\w+\s*=\s*require\([\"']koa[\"']\))",
        "https://koajs.com/#request", (
        "ctx.query[{key}]", "ctx.params[{key}]", "ctx.get({key})", "ctx.cookies.get({key})",
        "ctx.request.body[{key}]", "ctx.req.read()", "ctx.request.body.data[{key}]",
        "ctx.request.files[{key}].buffer", "ctx.request.files[{key}].name", "ctx.request.url",
        "ctx.host", "ctx.get(AUTHORIZATION)",
    )),
    _profile("javascript-nestjs", "javascript", "controller.ts",
        r"(?m)^\s*import\b.*?[\"']@nestjs/", "https://docs.nestjs.com/controllers", (
        "request.query[{key}]", "request.params[{key}]", "request.headers[{key}]",
        "request.cookies[{key}]", "request.body[{key}]", "request.rawBody",
        "request.body.data[{key}]", "request.file.buffer", "request.file.originalname",
        "request.originalUrl", "request.headers.host", "request.headers.authorization",
    )),
    _profile("javascript-fastify", "javascript", "server.js",
        r"(?m)^\s*(?:import\b.*?[\"']fastify[\"']|(?:const|let|var)\s+\w+\s*=\s*require\([\"']fastify[\"']\))",
        "https://fastify.dev/docs/latest/Reference/Request/", (
        "request.query[{key}]", "request.params[{key}]", "request.headers[{key}]",
        "request.cookies[{key}]", "request.body[{key}]", "request.raw.read()",
        "request.body.data[{key}]", "request.file().toBuffer()", "request.file().filename",
        "request.url", "request.hostname", "request.headers.authorization",
    )),
    _profile("javascript-hapi", "javascript", "server.js",
        r"(?m)^\s*(?:import\b.*?[\"']@hapi/hapi[\"']|require\([\"']@hapi/hapi[\"']\))",
        "https://hapi.dev/api/?v=21.4.0#request", (
        "request.query[{key}]", "request.params[{key}]", "request.headers[{key}]",
        "request.state[{key}]", "request.payload[{key}]", "request.raw.req.read()",
        "request.payload.data[{key}]", "request.payload[{key}].buffer", "request.payload[{key}].hapi.filename",
        "request.url.pathname", "request.info.host", "request.headers.authorization",
    )),
    _profile("java-spring", "java", "Controller.java",
        r"(?m)^\s*import\s+org\.springframework\.", "https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller.html", (
        "request.getParameter({key})", "pathVariables.get({key})", "request.getHeader({key})",
        "WebUtils.getCookie(request, {key}).getValue()", "request.getParameterMap().get({key})[0]",
        "request.getInputStream()", "objectMapper.readTree(request.getInputStream()).get({key})",
        "multipartFile.getBytes()", "multipartFile.getOriginalFilename()", "request.getRequestURI()",
        "request.getHeader(HOST)", "request.getHeader(AUTHORIZATION)",
    )),
    _profile("java-servlet", "java", "Servlet.java",
        r"(?m)^\s*import\s+(?:jakarta|javax)\.servlet\.", "https://jakarta.ee/specifications/servlet/6.1/apidocs/jakarta.servlet/jakarta/servlet/http/httpservletrequest", (
        "servletRequest.getParameter({key})", "servletRequest.getAttribute({key})",
        "servletRequest.getHeader({key})", "servletRequest.getCookies()[0].getValue()",
        "servletRequest.getParameterValues({key})[0]", "servletRequest.getInputStream()",
        "json.readTree(servletRequest.getInputStream()).get({key})", "part.getInputStream()",
        "part.getSubmittedFileName()", "servletRequest.getRequestURI()",
        "servletRequest.getHeader(HOST)", "servletRequest.getHeader(AUTHORIZATION)",
    )),
    _profile("java-jaxrs", "java", "Resource.java",
        r"(?m)^\s*import\s+jakarta\.ws\.rs\.", "https://jakarta.ee/specifications/restful-ws/4.0/apidocs/", (
        "uriInfo.getQueryParameters().getFirst({key})", "uriInfo.getPathParameters().getFirst({key})",
        "httpHeaders.getHeaderString({key})", "httpHeaders.getCookies().get({key}).getValue()",
        "formParams.getFirst({key})", "entityStream.readAllBytes()", "jsonEntity.get({key})",
        "formDataBodyPart.getValueAs(InputStream.class)", "formDataBodyPart.getContentDisposition().getFileName()",
        "uriInfo.getRequestUri().getPath()", "httpHeaders.getHeaderString(HOST)",
        "httpHeaders.getHeaderString(AUTHORIZATION)",
    )),
    _profile("java-vertx", "java", "Handler.java",
        r"(?m)^\s*import\s+io\.vertx\.", "https://vertx.io/docs/apidocs/io/vertx/ext/web/RoutingContext.html", (
        "routingContext.queryParams().get({key})", "routingContext.pathParam({key})",
        "routingContext.request().getHeader({key})", "routingContext.request().getCookie({key}).getValue()",
        "routingContext.request().formAttributes().get({key})", "routingContext.body().buffer()",
        "routingContext.body().asJsonObject().getValue({key})", "routingContext.fileUploads().iterator().next().uploadedFileName()",
        "routingContext.fileUploads().iterator().next().fileName()", "routingContext.request().uri()",
        "routingContext.request().host()", "routingContext.request().getHeader(AUTHORIZATION)",
    )),
    _profile("java-play", "java", "Controller.java",
        r"(?m)^\s*import\s+play\.", "https://www.playframework.com/documentation/3.0.x/api/java/play/mvc/Http.Request.html", (
        "request.getQueryString({key})", "request.attrs().get({key})", "request.header({key}).get()",
        "request.cookie({key}).get().value()", "request.body().asFormUrlEncoded().get({key})[0]",
        "request.body().asRaw().asBytes()", "request.body().asJson().get({key})",
        "request.body().asMultipartFormData().getFile({key}).getRef().path()", "request.body().asMultipartFormData().getFile({key}).getFilename()",
        "request.path()", "request.host()", "request.header(AUTHORIZATION).get()",
    )),
    _profile("csharp-aspnet-core", "csharp", "Controller.cs",
        r"(?m)^\s*using\s+Microsoft\.AspNetCore\.", "https://learn.microsoft.com/aspnet/core/fundamentals/http-context", (
        "Request.Query[{key}]", "Request.RouteValues[{key}]", "Request.Headers[{key}]",
        "Request.Cookies[{key}]", "Request.Form[{key}]", "Request.BodyReader.ReadAsync()",
        "JsonDocument.Parse(Request.Body).RootElement.GetProperty({key})", "Request.Form.Files.GetFile({key}).OpenReadStream()",
        "Request.Form.Files.GetFile({key}).FileName", "Request.Path.Value", "Request.Host.Value",
        "Request.Headers[AUTHORIZATION]",
    )),
    _profile("csharp-aspnet-mvc", "csharp", "Controller.cs",
        r"(?m)^\s*using\s+System\.Web\.Mvc\b", "https://learn.microsoft.com/previous-versions/aspnet/web-frameworks/", (
        "ControllerContext.HttpContext.Request.QueryString[{key}]", "RouteData.Values[{key}]",
        "ControllerContext.HttpContext.Request.Headers[{key}]", "ControllerContext.HttpContext.Request.Cookies[{key}].Value",
        "ControllerContext.HttpContext.Request.Form[{key}]", "ControllerContext.HttpContext.Request.InputStream",
        "JObject.Load(reader).GetValue({key})", "ControllerContext.HttpContext.Request.Files[{key}].InputStream",
        "ControllerContext.HttpContext.Request.Files[{key}].FileName", "ControllerContext.HttpContext.Request.RawUrl",
        "ControllerContext.HttpContext.Request.Headers[HOST]", "ControllerContext.HttpContext.Request.Headers[AUTHORIZATION]",
    )),
    _profile("csharp-minimal-api", "csharp", "Program.cs",
        r"(?m)^\s*(?:using\s+Microsoft\.AspNetCore\.|var\s+builder\s*=\s*WebApplication\.CreateBuilder)",
        "https://learn.microsoft.com/aspnet/core/fundamentals/minimal-apis", (
        "httpRequest.Query[{key}]", "httpRequest.RouteValues[{key}]", "httpRequest.Headers[{key}]",
        "httpRequest.Cookies[{key}]", "(await httpRequest.ReadFormAsync())[{key}]", "httpRequest.Body",
        "json.GetProperty({key})", "(await httpRequest.ReadFormAsync()).Files.GetFile({key}).OpenReadStream()",
        "(await httpRequest.ReadFormAsync()).Files.GetFile({key}).FileName", "httpRequest.Path.Value", "httpRequest.Host.Value",
        "httpRequest.Headers[AUTHORIZATION]",
    )),
    _profile("csharp-servicestack", "csharp", "Service.cs",
        r"(?m)^\s*using\s+ServiceStack\b", "https://docs.servicestack.net/http-utils", (
        "Request.QueryString[{key}]", "Request.Items[{key}]", "Request.Headers[{key}]",
        "Request.Cookies[{key}].Value", "Request.FormData[{key}]", "Request.InputStream",
        "requestDto.GetType().GetProperty({key}).GetValue(requestDto)", "Request.Files[0].InputStream",
        "Request.Files[0].FileName", "Request.PathInfo", "Request.Headers[HOST]", "Request.Headers[AUTHORIZATION]",
    )),
    _profile("csharp-fastendpoints", "csharp", "Endpoint.cs",
        r"(?m)^\s*using\s+FastEndpoints\b", "https://fast-endpoints.com/docs/misc-conveniences", (
        "Query<string>({key})", "Route<string>({key})", "HttpContext.Request.Headers[{key}]",
        "HttpContext.Request.Cookies[{key}]", "HttpContext.Request.Form[{key}]", "HttpContext.Request.Body",
        "dto.GetType().GetProperty({key}).GetValue(dto)", "Files.GetFile({key}).OpenReadStream()",
        "Files.GetFile({key}).FileName", "HttpContext.Request.Path.Value",
        "HttpContext.Request.Host.Value", "HttpContext.Request.Headers[AUTHORIZATION]",
    )),
    _profile("php-laravel", "php", "Controller.php",
        r"(?m)^\s*use\s+Illuminate\\", "https://laravel.com/docs/12.x/requests", (
        "$request->query({key})", "$request->route({key})", "$request->header({key})",
        "$request->cookie({key})", "$request->input({key})", "$request->getContent()",
        "$request->json({key})", "$request->file({key})->get()", "$request->file({key})->getClientOriginalName()",
        "$request->path()", "$request->header(HOST)", "$request->header(AUTHORIZATION)",
    )),
    _profile("php-symfony", "php", "Controller.php",
        r"(?m)^\s*use\s+Symfony\\Component\\HttpFoundation\\", "https://symfony.com/doc/current/components/http_foundation.html", (
        "$request->query->get({key})", "$request->attributes->get({key})", "$request->headers->get({key})",
        "$request->cookies->get({key})", "$request->request->get({key})", "$request->getContent()",
        "$request->toArray()[{key}]", "$request->files->get({key})->getContent()", "$request->files->get({key})->getClientOriginalName()",
        "$request->getPathInfo()", "$request->headers->get(HOST)", "$request->headers->get(AUTHORIZATION)",
    )),
    _profile("php-slim", "php", "Handler.php",
        r"(?m)^\s*use\s+Slim\\", "https://www.slimframework.com/docs/v4/objects/request.html", (
        "$request->getQueryParams()[{key}]", "$request->getAttribute({key})", "$request->getHeaderLine({key})",
        "$request->getCookieParams()[{key}]", "$request->getParsedBody()[{key}]", "$request->getBody()->getContents()",
        "$request->getParsedBody()[data][{key}]", "$uploadedFiles[{key}]->getStream()->getContents()",
        "$uploadedFiles[{key}]->getClientFilename()", "$request->getUri()->getPath()", "$request->getUri()->getHost()",
        "$request->getHeaderLine(AUTHORIZATION)",
    )),
    _profile("php-laminas", "php", "Handler.php",
        r"(?m)^\s*use\s+Laminas\\", "https://docs.laminas.dev/laminas-diactoros/v3/api/", (
        "$request->getQueryParams()[{key}]", "$request->getAttribute({key})", "$request->getHeaderLine({key})",
        "$request->getCookieParams()[{key}]", "$request->getParsedBody()[{key}]", "$request->getBody()->getContents()",
        "$request->getParsedBody()[data][{key}]", "$request->getUploadedFiles()[{key}]->getStream()->getContents()",
        "$request->getUploadedFiles()[{key}]->getClientFilename()", "$request->getUri()->getPath()", "$request->getUri()->getHost()",
        "$request->getHeaderLine(AUTHORIZATION)",
    )),
    _profile("php-yii", "php", "Controller.php",
        r"(?m)^\s*use\s+yii\\", "https://www.yiiframework.com/doc/api/2.0/yii-web-request", (
        "Yii::$app->request->get({key})", "Yii::$app->request->resolve()[1][{key}]",
        "Yii::$app->request->headers->get({key})", "Yii::$app->request->cookies->getValue({key})",
        "Yii::$app->request->post({key})", "Yii::$app->request->rawBody",
        "Yii::$app->request->bodyParams[{key}]", "UploadedFile::getInstanceByName({key})->tempName",
        "UploadedFile::getInstanceByName({key})->name", "Yii::$app->request->url", "Yii::$app->request->headers->get(HOST)",
        "Yii::$app->request->headers->get(AUTHORIZATION)",
    )),
)


FAMILIES: dict[str, Family] = {
    "sql": Family("sql", "database query injection", "injection/database", "CWE-89",
        "A05:2025 Injection", "CRITICAL", 0.97, ("v5.0.0-1.2.4",), 2,
        "Untrusted request data reaches a dynamic database query API.",
        "Use a parameterized query or a typed ORM operation; never interpolate query structure.",
        ("parameterize", "bind_param", "bindValue", "quoteIdentifier")),
    "command": Family("command", "OS command injection", "injection/command", "CWE-78",
        "A05:2025 Injection", "CRITICAL", 0.98, ("v5.0.0-1.2.5",), 9,
        "Untrusted request data reaches a shell or command interpreter.",
        "Avoid a shell; invoke a fixed executable with a validated argument array.",
        ("shlex.quote", "escapeshellarg", "CommandLineArgumentEscaper", "shellescape")),
    "xss": Family("xss", "cross-site scripting", "injection/browser", "CWE-79",
        "A05:2025 Injection", "HIGH", 0.94, ("v5.0.0-1.2.1",), 1,
        "Untrusted request data reaches an HTML-producing response or DOM sink.",
        "Use context-aware output encoding or a vetted HTML sanitizer at the final rendering boundary.",
        ("html.escape", "escapeHtml", "HtmlEncode", "htmlspecialchars", "sanitize")),
    "path": Family("path", "path traversal", "access-control/filesystem", "CWE-22",
        "A01:2025 Broken Access Control", "HIGH", 0.95, ("v5.0.0-5.3.2",), 6,
        "Untrusted request data controls a filesystem path.",
        "Resolve against a fixed root, reject absolute/traversal paths, and verify containment after canonicalization.",
        ("safe_join", "secure_filename", "getFullPathUnderRoot", "basename", "sanitizePath")),
    "ssrf": Family("ssrf", "server-side request forgery", "access-control/outbound-request", "CWE-918",
        "A01:2025 Broken Access Control", "CRITICAL", 0.96, ("v5.0.0-1.3.6",), 22,
        "Untrusted request data controls a server-side outbound URL.",
        "Allowlist schemes, hosts, ports, and paths; resolve and pin public addresses and revalidate redirects.",
        ("allowlisted_url", "validateOutboundUrl", "SafeUri", "validatedUri", "ssrfSafe")),
    "deserialize": Family("deserialize", "unsafe deserialization", "integrity/deserialization", "CWE-502",
        "A08:2025 Software or Data Integrity Failures", "CRITICAL", 0.96, ("v5.0.0-1.5.2",), 15,
        "Untrusted request data reaches an object deserializer capable of constructing types.",
        "Use a schema-based format and an explicit type allowlist; authenticate serialized state before parsing.",
        ("verify_signed", "verifySignature", "allowedTypes", "safe_load", "SafeDeserializer")),
    "code": Family("code", "dynamic code injection", "injection/code", "CWE-94",
        "A05:2025 Injection", "CRITICAL", 0.99, ("v5.0.0-1.3.2",), 10,
        "Untrusted request data reaches a dynamic code or expression evaluator.",
        "Remove runtime evaluation and replace it with explicit parsing and allowlisted dispatch.",
        ("allowlisted_expression", "validateExpression", "safeEvaluator", "parseOnly")),
    "directory": Family("directory", "LDAP/XPath query injection", "injection/directory-query", "CWE-90",
        "A05:2025 Injection", "HIGH", 0.94, ("v5.0.0-1.2.6",), None,
        "Untrusted request data reaches a directory or structured-query filter.",
        "Use parameterized/precompiled queries or the library's filter-value encoder.",
        ("escape_filter_chars", "escapeFilter", "EncodeFilter", "filter_var", "quoteXPath")),
    "redirect": Family("redirect", "open redirect", "access-control/redirect", "CWE-601",
        "A01:2025 Broken Access Control", "HIGH", 0.93, ("v5.0.0-3.7.2",), None,
        "Untrusted request data controls a redirect destination.",
        "Allowlist destinations or accept only normalized same-origin relative paths.",
        ("safe_redirect", "validateRedirect", "LocalRedirect", "url_for", "routeUrl")),
    "log": Family("log", "log injection", "logging/integrity", "CWE-117",
        "A09:2025 Security Logging & Alerting Failures", "MEDIUM", 0.82, ("v5.0.0-16.4.1",), None,
        "Untrusted request data reaches a textual logging boundary without visible neutralization.",
        "Use structured logging fields and neutralize CR/LF and control characters in untrusted values.",
        ("encode_log_value", "sanitizeForLog", "StructuredValue", "replaceNewlines")),
}


STANDARD_REFERENCES = (
    "https://owasp.org/Top10/2025/",
    "https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html",
    "https://github.com/OWASP/ASVS/tree/v5.0.0",
)


def _sink_pattern(template: str) -> str:
    """Compile a readable sink template into one bounded capture pattern."""
    if template.count("{value}") != 1:
        raise ValueError("sink template must contain exactly one {value}")
    parts = re.split(r"(\{value\}|\{any\})", template)
    compiled: list[str] = []
    for part in parts:
        if part == "{value}":
            quantifier = "{1,500}" if template.endswith("{value}") else "{1,500}?"
            compiled.append(r"(?P<value>[^\r\n;]" + quantifier + ")")
        elif part == "{any}":
            compiled.append(r"(?:[^,\r\n;]{1,240}?)")
        else:
            compiled.append(_literal_pattern(part))
    pattern = "".join(compiled)
    if template[0].isalnum() or template[0] in "_$":
        pattern = r"(?<![\w.$])" + pattern
    return pattern


def _make_sinks(language: str, rows: tuple[tuple[str, str, str, str], ...]) -> tuple[SinkDef, ...]:
    if len(rows) != 50:
        raise ValueError("%s must define exactly 50 sink operations" % language)
    sinks: list[SinkDef] = []
    for family, sid, label, template in rows:
        if family not in FAMILIES:
            raise ValueError("unknown sink family: " + family)
        words = re.findall(r"[A-Za-z_$][\w$]*", template.split("{value}", 1)[0])
        anchor = words[-1] if words else ""
        example = template.replace("{any}", '"fixed"').replace("{value}", "tainted")
        sinks.append(SinkDef(family, sid, label, template,
                             _sink_pattern(template), anchor, example))
    if len({sink.sid for sink in sinks}) != 50:
        raise ValueError("duplicate sink IDs for " + language)
    return tuple(sinks)


SINKS_BY_LANGUAGE: dict[str, tuple[SinkDef, ...]] = {
    "python": _make_sinks("python", (
        ("sql", "cursor-execute", "DB-API execute", "cursor.execute({value})"),
        ("sql", "cursor-executemany", "DB-API executemany", "cursor.executemany({value})"),
        ("sql", "connection-execute", "connection execute", "connection.execute({value})"),
        ("sql", "session-execute", "ORM session execute", "session.execute({value})"),
        ("sql", "engine-execute", "SQL engine execute", "engine.execute({value})"),
        ("command", "os-system", "os.system shell command", "os.system({value})"),
        ("command", "os-popen", "os.popen shell command", "os.popen({value})"),
        ("command", "subprocess-getoutput", "subprocess shell output", "subprocess.getoutput({value})"),
        ("command", "subprocess-getstatusoutput", "subprocess shell status/output", "subprocess.getstatusoutput({value})"),
        ("command", "subprocess-run-shell", "subprocess.run with shell", "subprocess.run({value}, shell=True)"),
        ("xss", "render-template-string", "Jinja template string", "render_template_string({value})"),
        ("xss", "django-mark-safe", "Django mark_safe", "mark_safe({value})"),
        ("xss", "markup-constructor", "Markup HTML constructor", "Markup({value})"),
        ("xss", "html-response", "HTML response body", "HTMLResponse({value})"),
        ("xss", "django-http-response", "Django raw HTTP response", "HttpResponse({value})"),
        ("path", "builtin-open", "filesystem open", "open({value})"),
        ("path", "path-read-text", "Path.read_text", "Path({value}).read_text()"),
        ("path", "flask-send-file", "send_file path", "send_file({value})"),
        ("path", "os-remove", "os.remove path", "os.remove({value})"),
        ("path", "shutil-rmtree", "recursive directory removal", "shutil.rmtree({value})"),
        ("ssrf", "requests-get", "requests GET URL", "requests.get({value})"),
        ("ssrf", "requests-post", "requests POST URL", "requests.post({value})"),
        ("ssrf", "httpx-get", "HTTPX GET URL", "httpx.get({value})"),
        ("ssrf", "urllib-urlopen", "urllib URL open", "urlopen({value})"),
        ("ssrf", "session-get", "HTTP session GET URL", "session.get({value})"),
        ("deserialize", "pickle-loads", "pickle object load", "pickle.loads({value})"),
        ("deserialize", "yaml-unsafe-load", "PyYAML unsafe load", "yaml.unsafe_load({value})"),
        ("deserialize", "yaml-full-load", "PyYAML full object load", "yaml.full_load({value})"),
        ("deserialize", "marshal-loads", "marshal object load", "marshal.loads({value})"),
        ("deserialize", "joblib-load", "joblib object load", "joblib.load({value})"),
        ("code", "builtin-eval", "Python eval", "eval({value})"),
        ("code", "builtin-exec", "Python exec", "exec({value})"),
        ("code", "interactive-runsource", "interactive interpreter source", "interpreter.runsource({value})"),
        ("code", "ipython-run-cell", "IPython cell execution", "get_ipython().run_cell({value})"),
        ("code", "jinja-template", "dynamic Jinja template render", "jinja2.Template({value}).render()"),
        ("directory", "ldap-search-filter", "LDAP search filter", "ldap_connection.search(search_filter={value})"),
        ("directory", "ldap3-search-filter", "ldap3 search filter", "connection.search(search_filter={value})"),
        ("directory", "ldap-search-s-filter", "python-ldap search filter", "ldap.search_s({any}, {any}, {value})"),
        ("directory", "lxml-xpath", "lxml XPath expression", "document.xpath({value})"),
        ("directory", "element-xpath", "element XPath expression", "element.xpath({value})"),
        ("redirect", "framework-redirect", "framework redirect", "redirect({value})"),
        ("redirect", "django-http-redirect", "Django redirect response", "HttpResponseRedirect({value})"),
        ("redirect", "starlette-redirect", "Starlette redirect response", "RedirectResponse({value})"),
        ("redirect", "aiohttp-found", "aiohttp redirect location", "HTTPFound(location={value})"),
        ("redirect", "location-header", "raw Location header", "response.headers[\"Location\"] = {value}"),
        ("log", "logger-info", "logger info message", "logger.info({value})"),
        ("log", "logger-warning", "logger warning message", "logger.warning({value})"),
        ("log", "logger-error", "logger error message", "logger.error({value})"),
        ("log", "logger-critical", "logger critical message", "logger.critical({value})"),
        ("log", "logging-info", "module logging message", "logging.info({value})"),
    )),
    "javascript": _make_sinks("javascript", (
        ("sql", "db-query", "database query", "db.query({value})"),
        ("sql", "connection-query", "connection query", "connection.query({value})"),
        ("sql", "client-query", "database client query", "client.query({value})"),
        ("sql", "sequelize-query", "Sequelize raw query", "sequelize.query({value})"),
        ("sql", "prisma-unsafe-query", "Prisma unsafe raw query", "prisma.$queryRawUnsafe({value})"),
        ("command", "child-exec", "child_process.exec shell", "child_process.exec({value})"),
        ("command", "child-exec-sync", "child_process.execSync shell", "child_process.execSync({value})"),
        ("command", "shelljs-exec", "ShellJS command", "shell.exec({value})"),
        ("command", "execa-command", "execa shell command", "execaCommand({value})"),
        ("command", "spawn-shell", "spawn with shell", "spawn({value}, {any}, { shell: true })"),
        ("xss", "inner-html", "DOM innerHTML assignment", "element.innerHTML = {value}"),
        ("xss", "outer-html", "DOM outerHTML assignment", "element.outerHTML = {value}"),
        ("xss", "document-write", "document.write HTML", "document.write({value})"),
        ("xss", "insert-adjacent-html", "insertAdjacentHTML", "element.insertAdjacentHTML({any}, {value})"),
        ("xss", "response-send", "raw web response send", "res.send({value})"),
        ("path", "fs-read-file", "filesystem read", "fs.readFile({value})"),
        ("path", "fs-write-file", "filesystem write", "fs.writeFile({value})"),
        ("path", "fs-unlink", "filesystem unlink", "fs.unlink({value})"),
        ("path", "fs-create-read-stream", "filesystem read stream", "fs.createReadStream({value})"),
        ("path", "response-send-file", "response file path", "res.sendFile({value})"),
        ("ssrf", "fetch-url", "Fetch URL", "fetch({value})"),
        ("ssrf", "axios-get", "Axios GET URL", "axios.get({value})"),
        ("ssrf", "http-get", "Node HTTP GET URL", "http.get({value})"),
        ("ssrf", "got-url", "Got request URL", "got({value})"),
        ("ssrf", "request-url", "request library URL", "request({value})"),
        ("deserialize", "node-serialize", "node-serialize object load", "nodeSerialize.unserialize({value})"),
        ("deserialize", "serialize-unserialize", "serialize object load", "serialize.unserialize({value})"),
        ("deserialize", "cryo-parse", "Cryo object graph load", "cryo.parse({value})"),
        ("deserialize", "funcster-deserialize", "Funcster function load", "funcster.deepDeserialize({value})"),
        ("deserialize", "jsyaml-full-schema", "js-yaml full schema load", "jsyaml.load({value}, { schema: jsyaml.DEFAULT_FULL_SCHEMA })"),
        ("code", "global-eval", "JavaScript eval", "eval({value})"),
        ("code", "function-constructor", "Function constructor", "new Function({value})"),
        ("code", "vm-run-context", "VM context execution", "vm.runInNewContext({value})"),
        ("code", "vm-script", "VM Script compilation", "new vm.Script({value})"),
        ("code", "string-timeout", "string timer execution", "setTimeout({value}, {any})"),
        ("directory", "ldap-search-filter", "LDAP search filter", "ldapClient.search({any}, {value})"),
        ("directory", "ldapjs-search-filter", "ldapjs search filter", "client.search({any}, {value})"),
        ("directory", "xpath-select", "XPath select expression", "xpath.select({value}, {any})"),
        ("directory", "document-evaluate", "DOM XPath evaluate", "document.evaluate({value}, {any})"),
        ("directory", "xml-find", "XML query expression", "xmlDocument.find({value})"),
        ("redirect", "express-redirect", "Express redirect", "res.redirect({value})"),
        ("redirect", "reply-redirect", "server reply redirect", "reply.redirect({value})"),
        ("redirect", "koa-redirect", "Koa redirect", "ctx.redirect({value})"),
        ("redirect", "location-assign", "browser location assignment", "location.assign({value})"),
        ("redirect", "window-location", "window location assignment", "window.location = {value}"),
        ("log", "console-log", "console log message", "console.log({value})"),
        ("log", "logger-info", "logger info message", "logger.info({value})"),
        ("log", "logger-warn", "logger warning message", "logger.warn({value})"),
        ("log", "logger-error", "logger error message", "logger.error({value})"),
        ("log", "logger-debug", "logger debug message", "logger.debug({value})"),
    )),
    "java": _make_sinks("java", (
        ("sql", "statement-execute", "JDBC execute", "statement.execute({value})"),
        ("sql", "statement-query", "JDBC executeQuery", "statement.executeQuery({value})"),
        ("sql", "statement-update", "JDBC executeUpdate", "statement.executeUpdate({value})"),
        ("sql", "native-query", "JPA native query", "entityManager.createNativeQuery({value})"),
        ("sql", "jdbc-query-list", "JdbcTemplate raw query", "jdbcTemplate.queryForList({value})"),
        ("command", "runtime-exec", "Runtime.exec command", "Runtime.getRuntime().exec({value})"),
        ("command", "process-builder", "ProcessBuilder execution", "new ProcessBuilder({value}).start()"),
        ("command", "command-line-parse", "Commons Exec command line", "CommandLine.parse({value})"),
        ("command", "process-builder-command", "ProcessBuilder command execution", "processBuilder.command({value}).start()"),
        ("command", "commons-executor", "Commons executor command", "executor.execute(CommandLine.parse({value}))"),
        ("xss", "writer-write", "servlet response write", "response.getWriter().write({value})"),
        ("xss", "writer-print", "servlet response print", "response.getWriter().print({value})"),
        ("xss", "jsp-out-print", "JSP raw output", "out.print({value})"),
        ("xss", "jsp-out-write", "JSP raw write", "out.write({value})"),
        ("xss", "html-content", "servlet response append", "response.getWriter().append({value})"),
        ("path", "file-input-stream", "file input stream", "new FileInputStream({value})"),
        ("path", "files-read-string", "Files.readString path", "Files.readString(Path.of({value}))"),
        ("path", "files-delete", "Files.delete path", "Files.delete(Path.of({value}))"),
        ("path", "files-input-stream", "Files.newInputStream path", "Files.newInputStream(Path.of({value}))"),
        ("path", "files-write-string", "Files.writeString path", "Files.writeString(Path.of({value}), {any})"),
        ("ssrf", "url-open", "URL stream request", "new URL({value}).openStream()"),
        ("ssrf", "rest-template-get", "RestTemplate GET URL", "restTemplate.getForObject({value}, {any})"),
        ("ssrf", "web-client-request", "WebClient outbound request", "WebClient.create({value}).get().retrieve()"),
        ("ssrf", "jsoup-connect", "Jsoup URL", "Jsoup.connect({value})"),
        ("ssrf", "http-request-uri", "Java HTTP request URI", "HttpRequest.newBuilder(URI.create({value}))"),
        ("deserialize", "commons-deserialize", "Commons object deserialize", "SerializationUtils.deserialize({value})"),
        ("deserialize", "xstream-xml", "XStream object load", "xstream.fromXML({value})"),
        ("deserialize", "snakeyaml-load", "SnakeYAML object load", "new Yaml().load({value})"),
        ("deserialize", "object-input-bytes", "Java object stream load", "new ObjectInputStream(new ByteArrayInputStream({value})).readObject()"),
        ("deserialize", "kryo-object", "Kryo class/object load", "kryo.readClassAndObject(new Input({value}))"),
        ("code", "script-engine-eval", "ScriptEngine eval", "scriptEngine.eval({value})"),
        ("code", "groovy-evaluate", "GroovyShell evaluate", "groovyShell.evaluate({value})"),
        ("code", "mvel-eval", "MVEL expression eval", "MVEL.eval({value})"),
        ("code", "jshell-eval", "JShell eval", "jshell.eval({value})"),
        ("code", "beanshell-eval", "BeanShell eval", "interpreter.eval({value})"),
        ("directory", "dir-context-search", "JNDI LDAP filter", "dirContext.search({any}, {value}, {any})"),
        ("directory", "ldap-template-search", "Spring LDAP filter", "ldapTemplate.search({any}, {value}, {any})"),
        ("directory", "xpath-evaluate", "XPath evaluate", "xpath.evaluate({value}, {any})"),
        ("directory", "select-nodes", "XML selectNodes", "document.selectNodes({value})"),
        ("directory", "jaxen-select", "Jaxen XPath", "new DOMXPath({value}).selectNodes({any})"),
        ("redirect", "send-redirect", "servlet redirect", "response.sendRedirect({value})"),
        ("redirect", "redirect-view", "Spring RedirectView", "new RedirectView({value})"),
        ("redirect", "jaxrs-see-other", "JAX-RS redirect", "Response.seeOther(URI.create({value}))"),
        ("redirect", "spring-redirect-prefix", "Spring redirect return", "return \"redirect:\" + {value}"),
        ("redirect", "location-header", "HTTP Location header", "response.setHeader(\"Location\", {value})"),
        ("log", "logger-info", "logger info message", "logger.info({value})"),
        ("log", "logger-warn", "logger warning message", "logger.warn({value})"),
        ("log", "logger-error", "logger error message", "logger.error({value})"),
        ("log", "logger-debug", "logger debug message", "logger.debug({value})"),
        ("log", "logger-trace", "logger trace message", "logger.trace({value})"),
    )),
    "csharp": _make_sinks("csharp", (
        ("sql", "sql-command", "SqlCommand text", "new SqlCommand({value})"),
        ("sql", "execute-sql-raw", "EF ExecuteSqlRaw", "database.ExecuteSqlRaw({value})"),
        ("sql", "from-sql-raw", "EF FromSqlRaw", "entities.FromSqlRaw({value})"),
        ("sql", "dapper-query", "Dapper Query", "connection.Query({value})"),
        ("sql", "dapper-execute", "Dapper Execute", "connection.Execute({value})"),
        ("command", "process-start", "Process.Start command", "Process.Start({value})"),
        ("command", "process-start-info", "ProcessStartInfo execution", "Process.Start(new ProcessStartInfo({value}))"),
        ("command", "powershell-script", "PowerShell script invocation", "powerShell.AddScript({value}).Invoke()"),
        ("command", "process-file-name", "process executable initialization", "Process.Start(new ProcessStartInfo { FileName = {value} })"),
        ("command", "process-arguments", "shell process argument initialization", "Process.Start(new ProcessStartInfo { FileName = \"cmd\", Arguments = {value}, UseShellExecute = true })"),
        ("xss", "response-write", "ASP.NET response write", "Response.Write({value})"),
        ("xss", "html-raw", "MVC Html.Raw", "Html.Raw({value})"),
        ("xss", "html-string", "HtmlString constructor", "new HtmlString({value})"),
        ("xss", "content-html", "HTML Content result", "Content({value}, \"text/html\")"),
        ("xss", "append-html", "raw HTML append", "html.AppendHtml({value})"),
        ("path", "file-read", "File.ReadAllText path", "File.ReadAllText({value})"),
        ("path", "file-write", "File.WriteAllText path", "File.WriteAllText({value}, {any})"),
        ("path", "file-delete", "File.Delete path", "File.Delete({value})"),
        ("path", "directory-files", "Directory.GetFiles path", "Directory.GetFiles({value})"),
        ("path", "physical-file", "physical file result", "PhysicalFile({value}, {any})"),
        ("ssrf", "http-get-async", "HttpClient GET URL", "httpClient.GetAsync({value})"),
        ("ssrf", "http-string-async", "HttpClient string URL", "httpClient.GetStringAsync({value})"),
        ("ssrf", "web-request-create", "WebRequest response", "WebRequest.Create({value}).GetResponse()"),
        ("ssrf", "rest-client", "RestClient outbound request", "new RestClient({value}).Execute({any})"),
        ("ssrf", "http-request-message", "HttpRequestMessage URL", "new HttpRequestMessage({any}, {value})"),
        ("deserialize", "binary-formatter", "BinaryFormatter object load", "formatter.Deserialize(new MemoryStream({value}))"),
        ("deserialize", "net-data-contract", "NetDataContract object load", "serializer.Deserialize(new MemoryStream({value}))"),
        ("deserialize", "los-formatter", "LosFormatter object load", "losFormatter.Deserialize({value})"),
        ("deserialize", "object-state-formatter", "ObjectStateFormatter load", "objectStateFormatter.Deserialize({value})"),
        ("deserialize", "json-type-name-all", "Json.NET polymorphic load", "JsonConvert.DeserializeObject({value}, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All })"),
        ("code", "csharp-script", "CSharpScript evaluation", "CSharpScript.EvaluateAsync({value})"),
        ("code", "datatable-compute", "DataTable expression", "dataTable.Compute({value}, {any})"),
        ("code", "codedom-source", "CodeDOM source compilation", "provider.CompileAssemblyFromSource({any}, {value})"),
        ("code", "csharp-script-run", "CSharpScript execution", "CSharpScript.RunAsync({value})"),
        ("code", "assembly-load", "dynamic assembly load", "Assembly.Load({value})"),
        ("directory", "directory-filter", "DirectorySearcher filter", "searcher.Filter = {value}"),
        ("directory", "ldap-search-request", "LDAP SearchRequest filter", "new SearchRequest({any}, {value}, {any})"),
        ("directory", "xpath-select", "XPathNavigator select", "navigator.Select({value})"),
        ("directory", "xml-select-nodes", "XmlNode XPath", "node.SelectNodes({value})"),
        ("directory", "linq-xpath-elements", "LINQ XML XPath", "element.XPathSelectElements({value})"),
        ("redirect", "response-redirect", "ASP.NET response redirect", "Response.Redirect({value})"),
        ("redirect", "mvc-redirect", "MVC Redirect", "Redirect({value})"),
        ("redirect", "redirect-permanent", "permanent redirect", "RedirectPermanent({value})"),
        ("redirect", "minimal-redirect", "minimal API redirect", "Results.Redirect({value})"),
        ("redirect", "redirect-result", "RedirectResult", "new RedirectResult({value})"),
        ("log", "log-information", "structured logger information", "logger.LogInformation({value})"),
        ("log", "log-warning", "structured logger warning", "logger.LogWarning({value})"),
        ("log", "log-error", "structured logger error", "logger.LogError({value})"),
        ("log", "log-critical", "structured logger critical", "logger.LogCritical({value})"),
        ("log", "console-write", "console output", "Console.WriteLine({value})"),
    )),
    "php": _make_sinks("php", (
        ("sql", "mysqli-query", "mysqli query", "mysqli_query({any}, {value})"),
        ("sql", "pdo-query", "PDO query", "$pdo->query({value})"),
        ("sql", "pdo-exec", "PDO exec", "$pdo->exec({value})"),
        ("sql", "laravel-select", "Laravel raw select", "DB::select({value})"),
        ("sql", "doctrine-query", "Doctrine executeQuery", "$connection->executeQuery({value})"),
        ("command", "system-command", "system command", "system({value})"),
        ("command", "exec-command", "exec command", "exec({value})"),
        ("command", "shell-exec-command", "shell_exec command", "shell_exec({value})"),
        ("command", "passthru-command", "passthru command", "passthru({value})"),
        ("command", "proc-open-command", "proc_open command", "proc_open({value}, {any}, {any})"),
        ("xss", "echo-output", "raw echo output", "echo {value}"),
        ("xss", "print-output", "raw print output", "print {value}"),
        ("xss", "printf-format", "printf output", "printf({value})"),
        ("xss", "html-string", "Laravel HtmlString", "new HtmlString({value})"),
        ("xss", "response-html", "raw response content", "new Response({value})"),
        ("path", "file-get-contents", "file read path", "file_get_contents({value})"),
        ("path", "file-put-contents", "file write path", "file_put_contents({value}, {any})"),
        ("path", "unlink-path", "unlink path", "unlink({value})"),
        ("path", "fopen-path", "fopen path", "fopen({value}, {any})"),
        ("path", "readfile-path", "readfile path", "readfile({value})"),
        ("ssrf", "curl-url", "cURL request URL", "curl_setopt({any}, CURLOPT_URL, {value})"),
        ("ssrf", "curl-init-url", "cURL initialization URL", "curl_init({value})"),
        ("ssrf", "guzzle-get", "Guzzle GET URL", "$client->get({value})"),
        ("ssrf", "guzzle-request", "Guzzle request URL", "$client->request({any}, {value})"),
        ("ssrf", "http-client-request", "HTTP client URL", "$httpClient->request({any}, {value})"),
        ("deserialize", "php-unserialize", "PHP object unserialize", "unserialize({value})"),
        ("deserialize", "igbinary-unserialize", "igbinary object load", "igbinary_unserialize({value})"),
        ("deserialize", "yaml-parse-object", "YAML object parse", "yaml_parse({value})"),
        ("deserialize", "zend-unserialize", "Zend serializer object load", "Zend\\Serializer\\Serializer::unserialize({value})"),
        ("deserialize", "symfony-unserialize", "Symfony serializer object load", "$serializer->deserialize({value}, {any}, {any})"),
        ("code", "eval-code", "PHP eval", "eval({value})"),
        ("code", "assert-code", "dynamic assert expression", "assert({value})"),
        ("code", "include-path", "dynamic include", "include {value}"),
        ("code", "require-path", "dynamic require", "require {value}"),
        ("code", "create-function", "dynamic function body", "create_function({any}, {value})"),
        ("directory", "ldap-search", "LDAP search filter", "ldap_search({any}, {any}, {value})"),
        ("directory", "ldap-list", "LDAP list filter", "ldap_list({any}, {any}, {value})"),
        ("directory", "dom-xpath-query", "DOMXPath query", "$xpath->query({value})"),
        ("directory", "simplexml-xpath", "SimpleXML XPath", "$xml->xpath({value})"),
        ("directory", "xquery-evaluate", "XQuery expression", "$xquery->evaluate({value})"),
        ("redirect", "location-header", "Location header", "header(\"Location: \" . {value})"),
        ("redirect", "laravel-redirect", "Laravel redirect", "redirect({value})"),
        ("redirect", "redirect-to", "redirect helper", "redirect()->to({value})"),
        ("redirect", "symfony-redirect", "Symfony RedirectResponse", "new RedirectResponse({value})"),
        ("redirect", "response-redirect", "response redirect", "$response->withHeader(\"Location\", {value})"),
        ("log", "error-log", "PHP error log", "error_log({value})"),
        ("log", "logger-info", "logger info message", "$logger->info({value})"),
        ("log", "logger-warning", "logger warning message", "$logger->warning({value})"),
        ("log", "logger-error", "logger error message", "$logger->error({value})"),
        ("log", "logger-debug", "logger debug message", "$logger->debug({value})"),
    )),
}


RULE_COUNT = sum(len(profile.sources) * len(SINKS_BY_LANGUAGE[profile.language])
                 for profile in PROFILES)
LANGUAGE_BY_EXTENSION = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "javascript", ".tsx": "javascript",
    ".java": "java", ".cs": "csharp", ".php": "php",
}
SOURCE_PRIORITY = {"auth": 4, "host": 3, "filename": 2, "header": 1}
ASSIGNMENT_RX = re.compile(
    r"^\s*(?:(?:const|let|var|final|String|Object|byte\[\]|var|string|dynamic|mixed)\s+)?"
    r"(?P<name>\$?[A-Za-z_][\w$]*)\s*=\s*(?P<rhs>.+)$")


def language_for(path: str) -> str:
    return LANGUAGE_BY_EXTENSION.get(Path(path).suffix.lower(), "")


def _rule_id(profile: Profile, source: SourceDef, sink: SinkDef) -> str:
    return "p23-%s-%s-%s-%s" % (
        profile.ecosystem, source.sid, sink.family, sink.sid)


@lru_cache(maxsize=None)
def _make_rule(profile: Profile, source: SourceDef, sink: SinkDef) -> FlowRule:
    family = FAMILIES[sink.family]
    semantic = json.dumps([
        PACK, profile.ecosystem, profile.language, source.sid, source.template,
        sink.family, sink.sid, sink.template, family.cwe,
    ], ensure_ascii=True, separators=(",", ":"))
    fingerprint = hashlib.sha256(semantic.encode("utf-8")).hexdigest()
    return FlowRule(
        rid=_rule_id(profile, source, sink), fingerprint=fingerprint,
        language=profile.language, ecosystem=profile.ecosystem,
        source_channel=source.sid, source_signature=source.template,
        sink_operation=sink.sid, sink_signature=sink.template,
        severity=family.severity, confidence=family.confidence,
        category=family.category, cwe=family.cwe,
        cwe_top25_2025_rank=family.cwe_top25_2025_rank,
        owasp=family.owasp, asvs=family.asvs,
        description=family.description, remediation=family.remediation,
        references=(profile.reference,) + STANDARD_REFERENCES,
    )


@lru_cache(maxsize=1)
def _materialize_rules() -> tuple[FlowRule, ...]:
    return tuple(
        _make_rule(profile, source, sink)
        for profile in PROFILES
        for source in profile.sources
        for sink in SINKS_BY_LANGUAGE[profile.language]
    )


class LazyRuleCatalog(Sequence[FlowRule]):
    """Sequence facade that makes count queries cheap and listing deterministic."""

    def __len__(self) -> int:
        return RULE_COUNT

    def __getitem__(self, index):
        return _materialize_rules()[index]

    def __iter__(self) -> Iterator[FlowRule]:
        return iter(_materialize_rules())


RULES: Sequence[FlowRule] = LazyRuleCatalog()


@lru_cache(maxsize=None)
def _source_regex(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def _mask_comments(text: str, language: str) -> str:
    """Mask comments while retaining offsets and string arguments used by APIs."""
    chars = list(text)
    quote = ""
    escaped = False
    block = False
    index = 0
    allow_hash = language in {"python", "php"}
    while index < len(chars):
        char = chars[index]
        nxt = chars[index + 1] if index + 1 < len(chars) else ""
        if block:
            if char == "*" and nxt == "/":
                chars[index] = chars[index + 1] = " "
                block = False
                index += 2
                continue
            if char not in "\r\n":
                chars[index] = " "
            index += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in "'\"`":
            quote = char
            index += 1
            continue
        if char == "/" and nxt == "*":
            chars[index] = chars[index + 1] = " "
            block = True
            index += 2
            continue
        if char == "/" and nxt == "/":
            while index < len(chars) and chars[index] not in "\r\n":
                chars[index] = " "
                index += 1
            continue
        if allow_hash and char == "#":
            while index < len(chars) and chars[index] not in "\r\n":
                chars[index] = " "
                index += 1
            continue
        index += 1
    return "".join(chars)


def _code_position(line: str, position: int) -> bool:
    quote = ""
    escaped = False
    for char in line[:max(0, position)]:
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in "'\"`":
            quote = char
    return not quote


def active_profiles(text: str, path: str) -> tuple[Profile, ...]:
    language = language_for(path)
    if not language:
        return ()
    masked = _mask_comments(text, language)
    active: list[Profile] = []
    for profile in PROFILES:
        if profile.language != language:
            continue
        try:
            match = re.search(profile.marker, masked)
        except re.error:
            continue
        if match:
            line_start = masked.rfind("\n", 0, match.start()) + 1
            line_end = masked.find("\n", match.start())
            line = masked[line_start:] if line_end < 0 else masked[line_start:line_end]
            if _code_position(line, match.start() - line_start):
                active.append(profile)
    return tuple(active)


def _top_level_commas(value: str) -> list[int]:
    positions: list[int] = []
    quote = ""
    escaped = False
    depth = 0
    pairs = {"(": ")", "[": "]", "{": "}"}
    closers = set(pairs.values())
    for index, char in enumerate(value):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in "'\"`":
            quote = char
        elif char in pairs:
            depth += 1
        elif char in closers:
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            positions.append(index)
    return positions


def _sanitized(value: str, family: Family) -> bool:
    lowered = value.lower()
    return any(name.lower() in lowered for name in family.sanitizers)


def _sql_parameter_position_safe(value: str, taint_offset: int) -> bool:
    commas = _top_level_commas(value)
    return bool(commas and taint_offset > commas[0])


def _source_hits(profile: Profile, lines: list[str]) -> dict[int, list[tuple[SourceDef, int, int]]]:
    hits: dict[int, list[tuple[SourceDef, int, int]]] = {}
    for line_index, line in enumerate(lines):
        by_span: dict[tuple[int, int], tuple[SourceDef, int, int]] = {}
        for source in profile.sources:
            for match in _source_regex(source.pattern).finditer(line):
                if not _code_position(line, match.start()):
                    continue
                row = (source, match.start(), match.end())
                key = (match.start(), match.end())
                previous = by_span.get(key)
                if previous is None or SOURCE_PRIORITY.get(source.sid, 0) > SOURCE_PRIORITY.get(previous[0].sid, 0):
                    by_span[key] = row
        if by_span:
            hits[line_index] = sorted(by_span.values(), key=lambda row: (row[1], -SOURCE_PRIORITY.get(row[0].sid, 0)))
    return hits


def _sink_hits(language: str, lines: list[str]) -> dict[int, list[tuple[SinkDef, re.Match[str]]]]:
    hits: dict[int, list[tuple[SinkDef, re.Match[str]]]] = {}
    for line_index, line in enumerate(lines):
        rows: list[tuple[SinkDef, re.Match[str]]] = []
        for sink in SINKS_BY_LANGUAGE[language]:
            if sink.anchor and sink.anchor not in line:
                continue
            for match in sink.regex().finditer(line):
                if _code_position(line, match.start()):
                    rows.append((sink, match))
        if rows:
            hits[line_index] = rows
    return hits


def _assignment(line: str) -> tuple[str, int] | None:
    match = ASSIGNMENT_RX.match(line)
    if not match:
        return None
    return match.group("name"), match.start("rhs")


def _reassigned(line: str, variable: str) -> bool:
    pattern = (r"^\s*(?:(?:const|let|var|final|String|Object|byte\[\]|var|string|dynamic|mixed)\s+)?"
               + re.escape(variable) + r"\s*=")
    return bool(re.search(pattern, line))


def _variable_offset(value: str, variable: str) -> int:
    match = re.search(r"(?<![\w$])" + re.escape(variable) + r"(?![\w$])", value)
    return match.start() if match else -1


def _finding(path: str, line: int, profile: Profile, source: SourceDef,
             sink: SinkDef) -> Finding:
    rule = _make_rule(profile, source, sink)
    family = FAMILIES[sink.family]
    return Finding(
        path=path, line=max(1, line), language=profile.language,
        rule=rule.rid, severity=family.severity, message=family.description,
        fix=family.remediation, category=family.category, cwe=family.cwe,
        owasp=family.owasp, confidence=family.confidence,
        evidence="%s flows to %s" % (source.label, sink.label),
        ecosystem=profile.ecosystem, source_channel=source.sid,
        sink_operation=sink.sid, fingerprint=rule.fingerprint,
        asvs=family.asvs, cwe_top25_2025_rank=family.cwe_top25_2025_rank,
    )


def analyze(text: str, path: str) -> list[Finding]:
    """Find direct and bounded same-variable request flows without 15K loops."""
    profiles = active_profiles(text, path)
    if not profiles:
        return []
    language = profiles[0].language
    masked = _mask_comments(text, language)
    lines = masked.splitlines()
    sinks_by_line = _sink_hits(language, lines)
    findings: list[Finding] = []
    seen: set[tuple] = set()

    for profile in profiles:
        sources_by_line = _source_hits(profile, lines)
        for line_index, source_rows in sources_by_line.items():
            line = lines[line_index]
            # Direct flow: the exact source expression occurs in the captured
            # dangerous argument, not merely elsewhere on the same line.
            for source, source_start, source_end in source_rows:
                for sink, sink_match in sinks_by_line.get(line_index, []):
                    value_start, value_end = sink_match.span("value")
                    # A bounded regex cannot balance nested calls. The sink's
                    # closing delimiter may therefore consume the source call's
                    # final delimiter; permit that exact boundary, but never a
                    # source that merely appears elsewhere on the line.
                    if not (value_start <= source_start and
                            source_end <= max(value_end, sink_match.end())):
                        continue
                    value = sink_match.group("value")
                    family = FAMILIES[sink.family]
                    relative = source_start - value_start
                    if _sanitized(value, family):
                        continue
                    if sink.family == "sql" and _sql_parameter_position_safe(value, relative):
                        continue
                    key = ("direct", line_index, source_start, source_end,
                           sink_match.start(), sink_match.end(), sink.sid)
                    if key not in seen:
                        seen.add(key)
                        findings.append(_finding(path, line_index + 1, profile, source, sink))

            # Local flow: bind the exact source to a simple local and inspect at
            # most six subsequent executable statements. Reassignment kills it.
            assignment = _assignment(line)
            if not assignment:
                continue
            variable, rhs_start = assignment
            bound_sources = [row for row in source_rows if row[1] >= rhs_start]
            if not bound_sources:
                continue
            source = max(bound_sources, key=lambda row: SOURCE_PRIORITY.get(row[0].sid, 0))[0]
            statements = 0
            for later in range(line_index + 1, len(lines)):
                candidate = lines[later]
                if not candidate.strip():
                    continue
                statements += 1
                if statements > MAX_FLOW_STATEMENTS:
                    break
                if _reassigned(candidate, variable):
                    break
                for sink, sink_match in sinks_by_line.get(later, []):
                    value = sink_match.group("value")
                    variable_offset = _variable_offset(value, variable)
                    if variable_offset < 0:
                        continue
                    family = FAMILIES[sink.family]
                    if _sanitized(value, family):
                        continue
                    if sink.family == "sql" and _sql_parameter_position_safe(value, variable_offset):
                        continue
                    key = ("local", line_index, variable, later,
                           sink_match.start(), sink_match.end(), sink.sid)
                    if key not in seen:
                        seen.add(key)
                        findings.append(_finding(path, later + 1, profile, source, sink))

    return sorted(findings, key=lambda row: (row.line, row.rule))


def catalog_summary() -> dict:
    by_language: dict[str, int] = {}
    by_family: dict[str, int] = {key: 0 for key in FAMILIES}
    for profile in PROFILES:
        count = len(profile.sources) * len(SINKS_BY_LANGUAGE[profile.language])
        by_language[profile.language] = by_language.get(profile.language, 0) + count
        for sink in SINKS_BY_LANGUAGE[profile.language]:
            by_family[sink.family] += len(profile.sources)
    return {
        "pack": PACK, "rules": RULE_COUNT, "profiles": len(PROFILES),
        "source_channels_per_profile": 12, "sinks_per_language": 50,
        "languages": dict(sorted(by_language.items())),
        "families": dict(sorted(by_family.items())),
        "materialized": bool(_materialize_rules.cache_info().currsize),
    }


def validate_catalog() -> list[str]:
    errors: list[str] = []
    if len(PROFILES) != 25:
        errors.append("expected 25 ecosystem profiles")
    if RULE_COUNT != 15_000 or len(RULES) != 15_000:
        errors.append("expected exactly 15,000 rules")
    for profile in PROFILES:
        if len(profile.sources) != 12:
            errors.append("%s does not have 12 sources" % profile.ecosystem)
        try:
            re.compile(profile.marker)
        except re.error as exc:
            errors.append("%s marker: %s" % (profile.ecosystem, exc))
        for source in profile.sources:
            try:
                match = _source_regex(source.pattern).search(source.example)
            except re.error as exc:
                errors.append("%s/%s source regex: %s" % (profile.ecosystem, source.sid, exc))
                continue
            if not match:
                errors.append("%s/%s source fixture does not match" % (profile.ecosystem, source.sid))
    for language, sinks in SINKS_BY_LANGUAGE.items():
        if len(sinks) != 50:
            errors.append("%s does not have 50 sinks" % language)
        for sink in sinks:
            try:
                match = sink.regex().search(sink.example)
            except re.error as exc:
                errors.append("%s/%s sink regex: %s" % (language, sink.sid, exc))
                continue
            if not match or "tainted" not in match.group("value"):
                errors.append("%s/%s sink fixture does not capture tainted value" % (language, sink.sid))
    rules = tuple(RULES)
    ids = {rule.rid for rule in rules}
    fingerprints = {rule.fingerprint for rule in rules}
    if len(ids) != RULE_COUNT:
        errors.append("rule IDs are not unique")
    if len(fingerprints) != RULE_COUNT:
        errors.append("semantic fingerprints are not unique")
    for rule in rules:
        if not (rule.cwe.startswith("CWE-") and rule.owasp.endswith(tuple([
                "Injection", "Broken Access Control", "Software or Data Integrity Failures",
                "Security Logging & Alerting Failures"]))):
            errors.append("incomplete taxonomy: " + rule.rid)
            break
        if not rule.references or not rule.description or not rule.remediation:
            errors.append("incomplete metadata: " + rule.rid)
            break
    return errors


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--list-rules", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        errors = validate_catalog()
        print(json.dumps({"ok": not errors, **catalog_summary(), "errors": errors}, indent=2))
        return 1 if errors else 0
    if args.list_rules:
        rows = [asdict(rule) for rule in RULES]
        print(json.dumps(rows, indent=2) if args.json else "\n".join(
            "%s [%s] %s" % (rule.rid, rule.severity, rule.description) for rule in RULES))
        return 0
    if not args.paths:
        print(json.dumps(catalog_summary(), indent=2))
        return 0
    findings: list[Finding] = []
    for raw in args.paths:
        target = Path(raw)
        candidates = [target] if target.is_file() else target.rglob("*") if target.is_dir() else []
        for path in candidates:
            if not path.is_file() or not language_for(str(path)):
                continue
            try:
                if path.stat().st_size > 2 * 1024 * 1024:
                    continue
                findings.extend(analyze(path.read_text(encoding="utf-8", errors="replace"), str(path)))
            except OSError as exc:
                print("precision catalog scan error: %s: %s" % (path, exc), file=os.sys.stderr)
                return 2
    if args.json:
        print(json.dumps([asdict(row) for row in findings], indent=2))
    else:
        for row in findings:
            print("%s:%d [%s] %s - %s" % (row.path, row.line, row.severity, row.rule, row.message))
    return min(len(findings), 250)


if __name__ == "__main__":
    raise SystemExit(main())
