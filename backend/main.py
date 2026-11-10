import asyncio
import csv
import hashlib
import html
import io
from importlib.metadata import version as package_version
import ipaddress
import json
import logging
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, AnyHttpUrl, ConfigDict, Field
import aiohttp

from backend.config import AuthWorkflowConfig, CrawlConfig
from backend.audit_log import append_audit_event
from backend.crawler.scope import TargetScope, ScopeValidationError
from backend.crawler.crawler import Crawler
from backend.privacy import redact_sensitive_text, sanitized_target_url
from backend.rate_limit import rate_limit_trace_config
from backend.scanners.manager import ScanManager
from backend.version import VERSION

logger = logging.getLogger(__name__)

def endpoint_inventory(endpoints: list[dict]) -> list[dict]:
    return [
        {
            "url": sanitized_target_url(str(endpoint.get("url", ""))),
            "method": endpoint.get("method", ""),
            "status": endpoint.get("status", 0),
            "content_type": endpoint.get("content_type", ""),
        }
        for endpoint in endpoints
    ]


def sanitized_findings(findings: list[dict]) -> list[dict]:
    sanitized = []
    for finding in findings:
        item = dict(finding)
        if item.get("url"):
            item["url"] = sanitized_target_url(str(item["url"]))
        for key, value in item.items():
            if isinstance(value, str):
                item[key] = redact_sensitive_text(value)
        item.setdefault(
            "assessment_type",
            "Indicador heurístico não confirmado.",
        )
        item["review_id"] = hashlib.sha256(
            str(item.get("id") or "|".join(
                str(item.get(key, ""))
                for key in ("scanner", "url", "title", "parameter")
            )).encode("utf-8")
        ).hexdigest()[:20]
        item.setdefault("review_status", "pending")
        item.setdefault("reviewer", "")
        item.setdefault("review_note", "")
        item["reproduction"] = {
            "method": str(item.get("method", "GET")),
            "url": item.get("url", "N/D"),
            "parameter": str(item.get("parameter", "")),
            "evidence": str(item.get("evidence", "")),
            "instructions": (
                "Repeat this observed request only in the authorized test environment; "
                "compare the returned behavior with the evidence and verification guidance. "
                "The scanner does not retain full request or response bodies."
            ),
        }
        sanitized.append(item)
    return sanitized


def sanitized_label(value: str | None) -> str:
    normalized = redact_sensitive_text(value or "")
    normalized = normalized.replace("\r", " ").replace("\n", " ")
    return " ".join(normalized.split())


def new_report_metadata(request: "StartScanRequest") -> dict:
    registered_scanner_count = len(ScanManager().scanners)
    return {
        "schema_version": "1.0",
        "run_id": str(uuid4()),
        "tool": "WebsiteAttack",
        "tool_version": VERSION,
        "python_version": sys.version.split()[0],
        "dependency_versions": {
            "aiohttp": package_version("aiohttp"),
            "fastapi": package_version("fastapi"),
            "reportlab": package_version("reportlab"),
        },
        "target": sanitized_target_url(str(request.target_url)),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
        "duration_seconds": None,
        "status": "running",
        "completeness": "in_progress",
        "scope": {
            "include_subdomains": False,
            "boundary": "same scheme, host and port",
        },
        "authorization": {
            "user_confirmation": request.agree_to_authorization,
            "basis": "explicit_user_attestation",
            "independently_verified": False,
            "scope": "target origin only",
        },
        "coverage": {
            "authenticated_requested": False,
            "authenticated_success": None,
            "authenticated_crawl": "not_supported",
            "crawl_methods": ["GET"],
            "private_route_coverage_confirmed": False,
            "passive_checks_only": True,
            "note": "A interface executa apenas verificações passivas sem autenticação.",
        },
        "framework_mapping": {
            "name": "OWASP Web Security Testing Guide",
            "url": "https://owasp.org/www-project-web-security-testing-guide/latest/",
            "mapping_level": "family/category only",
            "note": (
                "O alinhamento por família não equivale a executar ou validar "
                "um caso de teste WSTG específico."
            ),
        },
        "scanner_coverage": [],
        "settings": {
            "scan_profile": "broad_bounded",
            "max_depth": CrawlConfig().max_depth,
            "max_pages": CrawlConfig().max_pages,
            "concurrency": CrawlConfig().concurrency,
            "rate_limit_per_second": CrawlConfig().rate_limit_per_second,
            "authenticated_crawl_requested": False,
            "active_tests_enabled": False,
        },
        "counts": {},
        "scanner_validation": {
            "status": "not_certified",
            "general_precision_certified": False,
            "fixture_observations": 38,
            "registered_scanners": registered_scanner_count,
            "scanners_covered": [
                "Security headers",
                "CSP Configuration",
                "Session Cookie Security",
                "Cache-control issues",
                "Clickjacking",
            ],
            "fixture_results": {
                "expected_rule_findings": 17,
                "expected_no_findings": 21,
                "unexpected_findings": 0,
                "missed_expected_findings": 0,
            },
            "scope_note": (
                f"Os 38 casos de fixtures sintéticas locais verificam o comportamento "
                f"esperado das regras em apenas 5 de {registered_scanner_count} scanners. "
                "Não confirmam vulnerabilidades, não constituem benchmark independente "
                "ou representativo e não permitem inferir taxas gerais de falsos "
                "positivos/negativos."
            ),
        },
        "limitations": [
            "Os achados automatizados são indicadores e exigem verificação manual.",
            "A ferramenta não garante precisão absoluta; não confirma automaticamente que um indicador é uma vulnerabilidade real.",
            "As fixtures existentes verificam 38 casos sintéticos locais em 5 scanners; não confirmam vulnerabilidades nem constituem benchmark independente representativo ou taxas gerais de precisão certificadas.",
            "A ausência de achados não prova que o alvo é seguro.",
            "Erros, cancelamento ou cobertura parcial tornam a varredura incompleta.",
            "O estado de vulnerabilidade não é confirmado automaticamente; cada indicador requer triagem manual.",
            "A análise não é autenticada e executa apenas verificações passivas baseadas em pedidos GET.",
            "O escopo está limitado à mesma origem (esquema, host e porta) do URL introduzido; subdomínios não são incluídos.",
            "A ferramenta não confirma a identidade de quem autorizou a análise; a confirmação é uma declaração do utilizador.",
            "A análise não avalia design visual, acessibilidade, usabilidade, reservas, pagamentos ou código-fonte.",
        ],
    }


def finish_report_metadata(
    metadata: dict,
    progress: dict,
    status: str,
    findings: list,
    error_count: int,
) -> dict:
    finished_at = datetime.now(timezone.utc)
    started_at = datetime.fromisoformat(metadata["started_at"])
    metadata.update({
        "finished_at": finished_at.isoformat(),
        "duration_seconds": round((finished_at - started_at).total_seconds(), 2),
        "status": status,
        "completeness": (
            "execution_complete"
            if (
                status == "completed"
                and error_count == 0
                and progress.get("discovered_endpoints", 0) > 0
                and progress.get("tests_performed", 0)
                == progress.get("tests_total", 0)
            )
            else "partial"
        ),
        "counts": {
            "requests": progress.get("requests", 0),
            "endpoints": progress.get("discovered_endpoints", 0),
            "checks_completed": progress.get("tests_performed", 0),
            "checks_total": progress.get("tests_total", 0),
            "findings": len(findings),
            "errors": error_count,
        },
    })
    return metadata


def export_findings(
    findings,
    output_format: str = "json",
    metadata: dict | None = None,
    errors: list[dict] | None = None,
):
    findings_list = sanitized_findings(list(findings))
    report_metadata = metadata or {}
    scan_errors = errors or []
    if output_format == "csv":
        output = io.StringIO()
        fieldnames = [
            "id",
            "title",
            "category",
            "severity",
            "confidence",
            "status",
            "url",
            "method",
            "parameter",
            "evidence",
            "verification_guidance",
            "verification_tool",
            "impact",
            "impact_pt",
            "remediation",
            "run_id",
            "target",
            "authorization",
            "scan_status",
            "completeness",
            "started_at",
            "finished_at",
            "requests",
            "endpoints",
            "errors",
            "verification_status",
            "review_status",
            "reviewer",
            "review_note",
            "reproduction",
            "tool_version",
            "python_version",
            "dependency_versions",
            "settings",
            "limitations",
            "error_stage",
            "error_component",
            "error_type",
            "scanner_validation",
            "coverage",
            "scanner_coverage",
            "framework_mapping",
            "assessment_type",
            "scanner",
            "verification_playbook",
            "record_type",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        common_fields = {
            "run_id": report_metadata.get("run_id", ""),
            "target": report_metadata.get("target", ""),
            "authorization": json.dumps(
                report_metadata.get("authorization", {}),
                ensure_ascii=False,
                sort_keys=True,
            ),
            "scan_status": report_metadata.get("status", ""),
            "completeness": report_metadata.get("completeness", ""),
            "started_at": report_metadata.get("started_at", ""),
            "finished_at": report_metadata.get("finished_at", ""),
            "requests": report_metadata.get("counts", {}).get("requests", 0),
            "endpoints": report_metadata.get("counts", {}).get("endpoints", 0),
            "errors": report_metadata.get("counts", {}).get("errors", 0),
            "tool_version": report_metadata.get("tool_version", ""),
            "python_version": report_metadata.get("python_version", ""),
            "dependency_versions": json.dumps(
                report_metadata.get("dependency_versions", {}),
                ensure_ascii=False,
                sort_keys=True,
            ),
            "settings": json.dumps(report_metadata.get("settings", {}), ensure_ascii=False),
            "limitations": " | ".join(report_metadata.get("limitations", [])),
            "scanner_validation": json.dumps(
                report_metadata.get("scanner_validation", {}),
                ensure_ascii=False,
                sort_keys=True,
            ),
            "coverage": json.dumps(
                report_metadata.get("coverage", {}),
                ensure_ascii=False,
                sort_keys=True,
            ),
            "scanner_coverage": json.dumps(
                report_metadata.get("scanner_coverage", []),
                ensure_ascii=False,
                sort_keys=True,
            ),
            "framework_mapping": json.dumps(
                report_metadata.get("framework_mapping", {}),
                ensure_ascii=False,
                sort_keys=True,
            ),
        }

        def write_safe_row(row):
            for key, raw_value in row.items():
                value = "" if raw_value is None else str(raw_value)
                if key == "url" and value:
                    value = sanitized_target_url(value)
                value = redact_sensitive_text(value)
                if value.lstrip().startswith(("=", "+", "-", "@")):
                    value = "'" + value
                row[key] = value
            writer.writerow(row)

        write_safe_row({**common_fields, "record_type": "scan"})
        for finding in findings_list:
            row = dict(common_fields)
            row.update(finding)
            row.update({
                "reproduction": json.dumps(finding.get("reproduction", {}), ensure_ascii=False),
                "verification_playbook": json.dumps(
                    finding.get("verification_playbook", {}),
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                "verification_status": finding.get(
                    "verification_status", "Requires manual verification"
                ),
                "review_status": finding.get("review_status", "pending"),
                "record_type": "finding",
            })
            write_safe_row(row)
        for error in scan_errors:
            write_safe_row({
                **common_fields,
                "error_stage": error.get("stage", ""),
                "error_component": error.get("component", ""),
                "error_type": error.get("error_type", ""),
                "record_type": "error",
            })
        return output.getvalue()

    if output_format == "pdf":
        from io import BytesIO

        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            title="WebsiteAttack - Relatório de indicadores",
            author="WebsiteAttack",
        )
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "TitleStyle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            spaceAfter=14,
        )
        heading_style = ParagraphStyle(
            "HeadingStyle",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            spaceBefore=10,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "BodyStyle",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            spaceAfter=4,
        )

        story = [
            Paragraph("WebsiteAttack – Relatório preliminar de segurança", title_style),
            Paragraph(
                "Documento de uma análise automatizada, passiva e limitada ao escopo indicado. "
                "Não é uma certificação de segurança nem uma prova de que o site é seguro ou inseguro. "
                "Os indicadores precisam de validação manual; a precisão geral dos scanners não está certificada.",
                body_style,
            ),
            Spacer(1, 8 * mm),
        ]
        if report_metadata:
            review_statuses = [
                str(finding.get("review_status", "pending"))
                for finding in findings_list
            ]
            confirmed_by_reviewer = review_statuses.count("confirmed")
            awaiting_review = sum(
                status in {"pending", "needs_review"}
                for status in review_statuses
            )
            dismissed_by_reviewer = sum(
                status in {"false_positive", "not_reproducible"}
                for status in review_statuses
            )
            counts = report_metadata.get("counts", {})
            if report_metadata.get("status") != "completed":
                executive_summary = (
                    "A execução não terminou normalmente. Os dados são parciais e não devem "
                    "ser usados para conclusões sobre a segurança do site."
                )
            elif report_metadata.get("completeness") != "execution_complete":
                executive_summary = (
                    f"Foram observados {len(findings_list)} indicadores automáticos, mas a execução "
                    "foi parcial ou teve avisos. Estes indicadores não demonstram que o site é inseguro."
                )
            elif findings_list:
                executive_summary = (
                    f"Foram observados {len(findings_list)} indicadores automáticos em "
                    f"{counts.get('endpoints', 0)} endpoints. Isto não demonstra que o site é inseguro; "
                    "cada indicador requer validação manual antes de qualquer conclusão."
                )
            else:
                executive_summary = (
                    "Não foram observados indicadores pelos controlos executados. Isto não demonstra "
                    "que o site é seguro nem que todas as vulnerabilidades foram detetadas."
                )
            story.append(Paragraph("Resumo executivo", heading_style))
            story.append(Paragraph(html.escape(executive_summary), body_style))
            story.append(Paragraph(
                "Triagem registada: "
                f"{confirmed_by_reviewer} classificado(s) como confirmado(s) pelo revisor informado "
                f"(declaração não verificada independentemente); "
                f"{awaiting_review} por rever; "
                f"{dismissed_by_reviewer} classificado(s) como falso positivo/não reproduzível. "
                "A ferramenta não valida a identidade do revisor.",
                body_style,
            ))
            story.append(Paragraph(
                "Próximos passos: validar os indicadores em conjunto com o responsável pelo site, "
                "registar evidência reproduzível e só comunicar como vulnerabilidade aquilo que foi "
                "confirmado. Uma proposta de webdesign deve ser uma avaliação separada de design, "
                "acessibilidade e usabilidade; este relatório não avalia essas áreas.",
                body_style,
            ))
            authorization = report_metadata.get("authorization", {})
            story.append(Paragraph(
                "Autorização: "
                + (
                    "o utilizador declarou ter autorização expressa para o URL analisado; "
                    "a ferramenta não verifica a autorização ou a identidade do proprietário."
                    if authorization.get("user_confirmation")
                    else "não há confirmação de autorização registada."
                ),
                body_style,
            ))
            for label, value in (
                ("ID da varredura", report_metadata.get("run_id", "N/D")),
                ("Versão da ferramenta", report_metadata.get("tool_version", "N/D")),
                ("Versão do Python", report_metadata.get("python_version", "N/D")),
                (
                    "Dependências",
                    json.dumps(
                        report_metadata.get("dependency_versions", {}),
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                ),
                ("Alvo", report_metadata.get("target", "N/D")),
                ("Estado", report_metadata.get("status", "N/D")),
                ("Estado da execução (não é certificação de cobertura)", report_metadata.get("completeness", "N/D")),
                ("Início", report_metadata.get("started_at", "N/D")),
                ("Fim", report_metadata.get("finished_at", "N/D")),
            ):
                story.append(
                    Paragraph(
                        f"{label}: {html.escape(str(value))}",
                        body_style,
                    )
                )
            story.append(Paragraph(
                "Configuração: "
                + html.escape(json.dumps(report_metadata.get("settings", {}), ensure_ascii=False)),
                body_style,
            ))
            story.append(Paragraph(
                "Verificações executadas: "
                + html.escape(", ".join(report_metadata.get("scanner_selection", []))),
                body_style,
            ))
            coverage = report_metadata.get("coverage", {})
            story.append(Paragraph(
                "Cobertura e limites: "
                + html.escape(
                    f"análise não autenticada; apenas verificações passivas; "
                    f"{coverage.get('observed_endpoints', 0)} endpoints observados; "
                    f"métodos {', '.join(coverage.get('observed_methods', ['GET'])) or 'GET'}; "
                    "escopo limitado à origem indicada. Não inclui testes ativos, login, "
                    "rotas privadas ou revisão de código."
                ),
                body_style,
            ))
            story.append(Paragraph(
                "Alinhamento de metodologia: OWASP WSTG — apenas por família/categoria, "
                "sem alegação de execução de casos de teste específicos.",
                body_style,
            ))
            if report_metadata.get("scanner_coverage"):
                story.append(Paragraph("Mapa de verificações por scanner", heading_style))
                for scanner_record in report_metadata["scanner_coverage"]:
                    story.append(Paragraph(
                        html.escape(
                            f"{scanner_record.get('name', 'N/D')} — "
                            f"{scanner_record.get('mode', 'N/D')}; "
                            f"aplicável a {scanner_record.get('applicable_endpoints', 0)} de "
                            f"{scanner_record.get('endpoints_considered', 0)} endpoints; "
                            f"{scanner_record.get('validation_status', 'N/D')}; "
                            f"WSTG: {scanner_record.get('wstg_alignment', 'N/D')}"
                        ),
                        body_style,
                    ))
            scanner_validation = report_metadata.get("scanner_validation", {})
            if scanner_validation:
                story.append(Paragraph(
                    "Validação da precisão: "
                    + html.escape(str(scanner_validation.get("status", "desconhecida")))
                    + " — "
                    + html.escape(str(scanner_validation.get("scope_note", ""))),
                    body_style,
                ))
            counts = report_metadata.get("counts", {})
            story.append(Paragraph(
                "Requisições: {requests} | Endpoints: {endpoints} | "
                "Verificações: {checks_completed}/{checks_total} | "
                "Erros: {errors}".format(
                    requests=counts.get("requests", 0),
                    endpoints=counts.get("endpoints", 0),
                    checks_completed=counts.get("checks_completed", 0),
                    checks_total=counts.get("checks_total", 0),
                    errors=counts.get("errors", 0),
                ),
                body_style,
            ))
            for limitation in report_metadata.get("limitations", []):
                story.append(Paragraph(html.escape(str(limitation)), body_style))
            story.append(Spacer(1, 8 * mm))

        if not findings_list:
            story.append(Paragraph(
                "Nenhum indicador foi reportado. Isto não prova que o alvo esteja seguro.",
                body_style,
            ))
        else:
            for index, finding in enumerate(findings_list, start=1):
                story.append(Paragraph(f"{index}. {html.escape(str(finding.get('title', 'Indicador sem título')))}", heading_style))
                story.append(Paragraph(f"Categoria: {html.escape(str(finding.get('category', 'Sem categoria')))}", body_style))
                story.append(Paragraph(
                    "Classificação: "
                    + html.escape(str(finding.get("assessment_type", "Indicador heurístico não confirmado."))),
                    body_style,
                ))
                story.append(Paragraph(
                    "Scanner: " + html.escape(str(finding.get("scanner", "N/D"))),
                    body_style,
                ))
                story.append(Paragraph(f"Severidade: {html.escape(str(finding.get('severity', 'Informational')))}", body_style))
                story.append(Paragraph(f"Estado: {html.escape(str(finding.get('status', 'Potential')))}", body_style))
                story.append(Paragraph(
                    "Revisão humana: "
                    + html.escape(str(finding.get("review_status", "pending")))
                    + (
                        " — " + html.escape(str(finding.get("review_note", "")))
                        if finding.get("review_note")
                        else ""
                    ),
                    body_style,
                ))
                story.append(Paragraph(
                    f"Pontuação heurística do scanner: "
                    f"{html.escape(str(finding.get('confidence', 0)))}%",
                    body_style,
                ))
                story.append(Paragraph("Validação: requer verificação manual", body_style))
                reproduction = finding.get("reproduction", {})
                story.append(Paragraph(
                    "Reprodução controlada: "
                    + html.escape(str(reproduction.get("instructions", "Requer verificação manual."))),
                    body_style,
                ))
                story.append(Paragraph(
                    f"URL: {html.escape(sanitized_target_url(str(finding.get('url', 'N/D'))))}",
                    body_style,
                ))
                story.append(Paragraph(f"Evidência: {html.escape(str(finding.get('evidence', 'N/D')))}", body_style))
                story.append(Paragraph(f"Verificação: {html.escape(str(finding.get('verification_guidance', 'N/D')))}", body_style))
                story.append(Paragraph(f"Ferramentas de apoio (não confirmam sozinhas): {html.escape(str(finding.get('verification_tool', 'Burp Suite + OWASP ZAP')))}", body_style))
                playbook = finding.get("verification_playbook", {})
                if playbook:
                    story.append(Paragraph("Como verificar (apenas em ambiente autorizado)", heading_style))
                    for step in playbook.get("steps", []):
                        story.append(Paragraph("• " + html.escape(str(step)), body_style))
                    story.append(Paragraph(
                        "<b>Critério de confirmação:</b> "
                        + html.escape(str(playbook.get("confirmation_criteria", ""))),
                        body_style,
                    ))
                    story.append(Paragraph(
                        "<b>Verificações contra falsos positivos:</b> "
                        + html.escape(str(playbook.get("false_positive_checks", ""))),
                        body_style,
                    ))
                story.append(Paragraph(f"Impacto no site: {html.escape(str(finding.get('impact_pt', finding.get('impact', 'Sem impacto informado.'))))}", body_style))
                story.append(Paragraph(f"Remediação: {html.escape(str(finding.get('remediation', 'Rever a lógica da aplicação e aplicar validação/escape adequados.')))}", body_style))
                story.append(Spacer(1, 6 * mm))

        if scan_errors:
            story.append(Paragraph("Falhas e avisos", heading_style))
            for error in scan_errors:
                description = (
                    f"{error.get('stage', 'varredura')} — "
                    f"{error.get('component', 'componente')} "
                    f"({error.get('error_type', 'erro')})"
                )
                story.append(Paragraph(html.escape(description), body_style))

        doc.build(story)
        buffer.seek(0)
        return buffer

    return {
        "report": report_metadata,
        "findings": findings_list,
        "count": len(findings_list),
    }

app = FastAPI(title="WebsiteAttack")

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


def is_loopback_address(address: str | None) -> bool:
    if not address:
        return False
    if address.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def is_allowed_local_host(host: str | None) -> bool:
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@app.middleware("http")
async def require_loopback_client(request: Request, call_next):
    client_host = request.client.host if request.client else None
    if not is_loopback_address(client_host) or not is_allowed_local_host(
        request.url.hostname
    ):
        return JSONResponse(
            status_code=403,
            content={"detail": "WebsiteAttack only accepts connections from this computer."},
        )
    response = await call_next(request)
    if request.url.path.startswith("/api/") or request.url.path in {
        "/",
        "/styles.css",
        "/app.js",
    }:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    return response


class StartScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: AnyHttpUrl
    agree_to_authorization: bool = False


class FindingReviewRequest(BaseModel):
    status: Literal[
        "confirmed",
        "false_positive",
        "not_reproducible",
        "accepted_risk",
        "needs_review",
    ]
    reviewer: str = Field(min_length=1, max_length=100)
    note: str = Field(default="", max_length=2000)


current_scan = {
    "status": "idle",
    "progress": {},
    "results": None,
    "task": None,
}

@app.get("/")
async def ui():
    return FileResponse(FRONTEND_DIR / "index.html")

@app.get("/styles.css")
async def styles():
    return FileResponse(FRONTEND_DIR / "styles.css")

@app.get("/app.js")
async def app_js():
    return FileResponse(FRONTEND_DIR / "app.js")

@app.post("/api/scan")
async def start_scan(request: StartScanRequest):
    if current_scan["status"] == "running":
        raise HTTPException(
            status_code=409,
            detail="A scan is already running. Wait for it to finish or cancel it first.",
        )
    if not request.agree_to_authorization:
        raise HTTPException(status_code=400, detail="Authorization confirmation is required.")
    try:
        scope = TargetScope(str(request.target_url))
    except ScopeValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    config = CrawlConfig()
    crawler = Crawler(scope, config)
    current_scan["progress"] = crawler.progress
    current_scan["progress"]["status"] = "running"
    current_scan["status"] = "running"
    current_scan["results"] = None
    report_metadata = new_report_metadata(request)
    try:
        append_audit_event(
            "scan_started",
            {
                "run_id": report_metadata["run_id"],
                "target": report_metadata["target"],
                "scope": report_metadata["scope"],
                "settings": report_metadata["settings"],
            },
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        logger.error("Could not write scan audit event (%s)", type(exc).__name__)
        raise HTTPException(
            status_code=503,
            detail="The local audit log could not be written; the scan was not started.",
        ) from exc
    current_scan["report_metadata"] = report_metadata
    auth_config = AuthWorkflowConfig()
    auth_config_display = {"enabled": False}
    task = asyncio.create_task(
        run_crawl(
            crawler,
            str(request.target_url),
            auth_config,
            None,
            None,
            auth_config_display,
            report_metadata,
        )
    )
    current_scan["task"] = task
    return {"status": "started", "progress": "/api/progress"}

@app.get("/api/progress")
async def scan_progress():
    return current_scan["progress"]

@app.post("/api/cancel")
async def cancel_scan():
    task = current_scan.get("task")
    if task and not task.done():
        metadata = current_scan.get("report_metadata", {})
        try:
            append_audit_event(
                "scan_cancel_requested",
                {
                    "run_id": metadata.get("run_id"),
                    "target": metadata.get("target"),
                },
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            logger.error("Could not write cancellation audit event (%s)", type(exc).__name__)
            raise HTTPException(
                status_code=503,
                detail="The cancellation could not be audited; it was not requested.",
            ) from exc
        task.cancel()
        return {"status": "cancelled"}
    return {"status": "no active scan"}

async def run_crawl(
    crawler: Crawler,
    start_url: str,
    auth_config: AuthWorkflowConfig,
    username: str | None,
    password: str | None,
    auth_config_display: dict,
    report_metadata: dict,
    auth_requested: bool = False,
    enable_active_tests: bool = False,
):
    scanner = None
    auth_result = None
    auth_errors = []
    try:
        scanner = ScanManager()
        try:
            target_address = ipaddress.ip_address(crawler.state.scope.host)
            unsafe_cookie_jar = target_address.is_loopback
        except ValueError:
            unsafe_cookie_jar = False
        session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15, connect=5, sock_read=10),
            cookie_jar=aiohttp.CookieJar(unsafe=unsafe_cookie_jar),
            trace_configs=[
                rate_limit_trace_config(
                    crawler.rate_limiter,
                    crawler.state.scope,
                    current_scan["progress"],
                )
            ],
        )
        async with session:
            if auth_requested:
                current_scan["progress"]["module"] = "authentication"
                try:
                    auth_result = await scanner.authenticate_session(
                        session,
                        auth_config,
                        username,
                        password,
                        base_url=start_url,
                        scope=crawler.state.scope,
                    )
                    if not auth_result or not auth_result.get("success"):
                        auth_errors.append({
                            "stage": "authentication",
                            "component": "login workflow",
                            "error_type": "AuthenticationUnconfirmed",
                        })
                        current_scan["progress"]["error_count"] = (
                            current_scan["progress"].get("error_count", 0) + 1
                        )
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning(
                        "Authentication workflow failed (%s)", type(exc).__name__
                    )
                    auth_errors.append({
                        "stage": "authentication",
                        "component": "login workflow",
                        "error_type": type(exc).__name__,
                    })
                    current_scan["progress"]["error_count"] = (
                        current_scan["progress"].get("error_count", 0) + 1
                    )
                finally:
                    username = None
                    password = None

            results = await crawler.crawl(start_url, session=session)
            current_scan["progress"]["crawl_completed"] = True
            current_scan["progress"]["completed"] = False
            current_scan["progress"]["module"] = "security testing"
            passive_only = auth_requested or not enable_active_tests
            selected_scanners = [
                item for item in scanner.scanners
                if not passive_only or item.name in scanner.PASSIVE_SCANNER_NAMES
            ]
            current_scan["progress"]["tests_total"] = (
                len(selected_scanners) * len(results)
            )
            current_scan["progress"]["tests_performed"] = 0
            scan_result = await scanner.execute(
                results,
                progress=current_scan["progress"],
                auth=auth_config,
                rate_limiter=crawler.rate_limiter,
                scope=crawler.state.scope,
                session=session,
                passive_only=passive_only,
                auth_result=auth_result,
            )
            current_scan["results"] = {
                "endpoints": endpoint_inventory(results),
                "findings": sanitized_findings(scan_result["findings"]),
                "summary": scan_result["summary"],
                "auth_config": auth_config_display,
                "auth": scan_result["auth"],
                "errors": auth_errors + crawler.state.errors + scan_result["errors"],
                "error_count": (
                    len(auth_errors)
                    + crawler.state.error_count
                    + scan_result["error_count"]
                ),
                "status": "completed",
            }
            report_metadata["coverage"]["authenticated_success"] = bool(
                auth_result and auth_result.get("success")
            )
            report_metadata["coverage"]["authenticated_crawl"] = (
                "authenticated_get_only"
                if auth_result and auth_result.get("success")
                else "authentication_unconfirmed"
                if auth_requested
                else "unauthenticated"
            )
            report_metadata["coverage"]["private_route_coverage_confirmed"] = False
            report_metadata["coverage"]["observed_endpoints"] = len(results)
            report_metadata["coverage"]["observed_methods"] = sorted({
                str(endpoint.get("method", "GET")).upper()
                for endpoint in results
            })
            report_metadata["scanner_coverage"] = scan_result["summary"][
                "scanner_coverage"
            ]
            report_metadata["scanner_selection"] = scan_result["summary"]["scanners"]
            report_metadata["settings"]["scanner_mode"] = scan_result["summary"]["mode"]
            current_scan["status"] = "completed"
    except asyncio.CancelledError:
        current_scan["progress"]["module"] = "cancelled"
        current_scan["status"] = "cancelled"
        current_scan["results"] = {
            "endpoints": endpoint_inventory(list(crawler.state.endpoints.values())),
            "findings": sanitized_findings(scanner.findings if scanner else []),
            "errors": auth_errors + crawler.state.errors + (scanner.errors if scanner else []),
            "error_count": current_scan["progress"].get("error_count", 0),
            "status": "cancelled",
        }
    except Exception as exc:
        logger.error("Scan pipeline failed (%s)", type(exc).__name__)
        current_scan["progress"]["module"] = "failed"
        current_scan["progress"]["error_count"] = (
            current_scan["progress"].get("error_count", 0) + 1
        )
        current_scan["status"] = "failed"
        current_scan["results"] = {
            "endpoints": endpoint_inventory(list(crawler.state.endpoints.values())),
            "findings": sanitized_findings(scanner.findings if scanner else []),
            "errors": auth_errors + crawler.state.errors
            + (scanner.errors if scanner else [])
            + [{
                "stage": "scan",
                "component": "pipeline",
                "error_type": type(exc).__name__,
            }],
            "error_count": current_scan["progress"]["error_count"],
            "status": "failed",
        }
    finally:
        if scanner is not None and current_scan.get("results"):
            report_metadata["scanner_selection"] = (
                current_scan["results"].get("summary", {}).get("scanners", [])
            )
            report_metadata["settings"]["scanner_mode"] = (
                current_scan["results"].get("summary", {}).get("mode", "unknown")
            )
            report_metadata["scanner_coverage"] = current_scan["results"].get(
                "summary", {}
            ).get("scanner_coverage", report_metadata.get("scanner_coverage", []))
        current_scan["progress"]["completed"] = True
        current_scan["progress"]["status"] = current_scan["status"]
        results = current_scan.get("results") or {}
        try:
            append_audit_event(
                "scan_finished",
                {
                    "run_id": report_metadata.get("run_id"),
                    "target": report_metadata.get("target"),
                    "status": current_scan["status"],
                    "findings": len(results.get("findings", [])),
                    "errors": results.get("error_count", 0),
                },
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            logger.error("Could not write scan completion audit event (%s)", type(exc).__name__)
            results.setdefault("errors", []).append({
                "stage": "audit",
                "component": "local audit log",
                "error_type": type(exc).__name__,
            })
            results["error_count"] = results.get("error_count", 0) + 1
            current_scan["progress"]["error_count"] = (
                current_scan["progress"].get("error_count", 0) + 1
            )
        metadata = finish_report_metadata(
            report_metadata,
            current_scan["progress"],
            current_scan["status"],
            results.get("findings", []),
            results.get("error_count", 0),
        )
        results["report"] = metadata
        current_scan["results"] = results
        current_scan["task"] = None

@app.get("/api/results")
async def scan_results():
    if current_scan.get("results") is None:
        raise HTTPException(status_code=409, detail="No completed scan report is available.")
    return current_scan["results"]


@app.post("/api/findings/{review_id}/review")
async def review_finding(review_id: str, request: FindingReviewRequest):
    results = current_scan.get("results")
    if results is None:
        raise HTTPException(status_code=409, detail="No completed scan report is available.")
    finding = next(
        (
            item
            for item in results.get("findings", [])
            if item.get("review_id") == review_id
        ),
        None,
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding was not found in this report.")
    metadata = results.get("report", {})
    clean_note = sanitized_label(request.note)
    clean_reviewer = sanitized_label(request.reviewer)
    if not clean_reviewer:
        raise HTTPException(status_code=400, detail="A reviewer name is required.")
    if request.status in {"confirmed", "false_positive", "not_reproducible"} and not clean_note:
        raise HTTPException(
            status_code=400,
            detail="Add a short verification note before saving this review outcome.",
        )
    try:
        append_audit_event(
            "finding_reviewed",
            {
                "run_id": metadata.get("run_id"),
                "operator": clean_reviewer,
                "finding_id": review_id,
                "review_status": request.status,
            },
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        logger.error("Could not write finding review audit event (%s)", type(exc).__name__)
        raise HTTPException(
            status_code=503,
            detail="The review could not be saved because the local audit log is unavailable.",
        ) from exc
    finding["review_status"] = request.status
    finding["reviewer"] = clean_reviewer
    finding["review_note"] = clean_note
    finding["verification_status"] = {
        "confirmed": "Confirmed by reviewer; self-reported, see review note.",
        "false_positive": "Reviewed as false positive; self-reported, see review note.",
        "not_reproducible": "Not reproduced by reviewer; self-reported, see review note.",
        "accepted_risk": "Risk accepted by reviewer; self-reported.",
        "needs_review": "Requires manual verification.",
    }[request.status]
    return {
        "review_id": review_id,
        "review_status": request.status,
        "reviewer": finding["reviewer"],
        "review_note": clean_note,
        "verification_status": finding["verification_status"],
    }


@app.get("/api/export")
async def export_results(output_format: str = "json"):
    if output_format not in {"json", "csv", "pdf"}:
        raise HTTPException(status_code=400, detail="Unsupported export format.")
    results = current_scan.get("results")
    if results is None:
        raise HTTPException(status_code=409, detail="No completed scan report is available.")
    metadata = results.get("report", {})
    payload = export_findings(
        results.get("findings", []),
        output_format=output_format,
        metadata=metadata,
        errors=results.get("errors", []),
    )
    if output_format == "csv":
        return StreamingResponse(
            iter([payload]),
            media_type="text/csv",
            headers={
                "Content-Disposition": (
                    f"attachment; filename=websiteattack-{metadata.get('run_id', 'report')}.csv"
                )
            },
        )
    if output_format == "pdf":
        pdf_bytes = payload.getvalue()
        return StreamingResponse(
            iter([pdf_bytes]),
            media_type="application/pdf",
            headers={
                "Content-Disposition": (
                    f"attachment; filename=websiteattack-{metadata.get('run_id', 'report')}.pdf"
                )
            },
        )
    report = {
        "report": metadata,
        "summary": results.get("summary", {}),
        "endpoints": results.get("endpoints", []),
        "findings": results.get("findings", []),
        "errors": results.get("errors", []),
        "error_count": results.get("error_count", 0),
    }
    return Response(
        content=json.dumps(report, ensure_ascii=False, indent=2),
        media_type="application/json",
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=False)
