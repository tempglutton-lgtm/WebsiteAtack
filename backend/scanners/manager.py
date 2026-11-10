import asyncio
import logging
from contextlib import AsyncExitStack
from urllib.parse import urljoin

import aiohttp
from typing import Any, Dict, List, Optional

from backend.config import AuthWorkflowConfig
from backend.crawler.parser import SimpleHTMLLinkParser
from backend.crawler.scope import TargetScope
from backend.http_limits import read_response_body
from backend.rate_limit import RequestRateLimiter, rate_limit_trace_config
from backend.scanners.registry import all_scanners

logger = logging.getLogger(__name__)


class FindingValidator:
    def validate(self, finding: Dict[str, Any]) -> bool:
        if not isinstance(finding, dict):
            return False
        return bool(
            finding.get("title")
            and finding.get("url")
            and finding.get("evidence")
            and finding.get("verification_guidance")
        )

class ScanManager:
    PASSIVE_SCANNER_NAMES = {
        "CSP Configuration",
        "CSRF Protection",
        "CORS Configuration",
        "Cache-control issues",
        "Clickjacking",
        "Endpoint discovery",
        "Method Access Control",
        "Parameter discovery",
        "Security headers",
        "Sensitive Route Discovery",
        "Server Header Disclosure",
        "Session Cookie Security",
        "Technology fingerprinting",
    }

    def __init__(self):
        self.scanners = all_scanners()
        self.findings: List[dict] = []
        self.errors: List[dict] = []
        self.finding_validator = FindingValidator()

    @staticmethod
    def _wstg_alignment(scanner: Any) -> str:
        module_parts = scanner.__class__.__module__.split(".")
        family = module_parts[2] if len(module_parts) > 2 else ""
        alignments = {
            "access_control": "Authorization Testing",
            "authentication": "Authentication Testing / Session Management Testing",
            "api": "API-related checks; no one-to-one WSTG test mapping claimed",
            "client_side": "Client-side Testing",
            "configuration": "Configuration and Deployment Management Testing",
            "injection": "Input Validation Testing",
            "recon": "Information Gathering",
            "server_side": "Server-side behavior; no one-to-one WSTG test mapping claimed",
            "xss": "Client-side Testing / Input Validation Testing",
            "disclosure": "Configuration and Deployment Management Testing",
        }
        return alignments.get(
            family,
            "No category-level mapping assigned",
        )

    @staticmethod
    def _family_limitations(scanner: Any) -> str:
        module_parts = scanner.__class__.__module__.split(".")
        family = module_parts[2] if len(module_parts) > 2 else ""
        limitations = {
            "access_control": "Não compara automaticamente duas ou mais identidades/perfis nem prova uma violação de autorização.",
            "api": "Não prova cobertura integral do schema, das operações ou da matriz de autorização da API.",
            "authentication": "Não valida todos os fluxos de autenticação, recuperação de conta ou invalidação entre sessões.",
            "client_side": "Não confirma comportamento em runtime de todos os browsers nem execução de código no browser.",
            "configuration": "Uma configuração observada não prova impacto explorável nem considera sempre controlos compensatórios.",
            "disclosure": "A presença de metadados não prova exposição de informação sensível ou impacto.",
            "injection": "Não confirma execução server-side nem acesso/alteração de dados; sinais heurísticos requerem validação manual.",
            "recon": "A descoberta limita-se aos recursos alcançados dentro do escopo e limites desta execução.",
            "server_side": "Não acede a serviços internos ou ficheiros do alvo; o efeito server-side não é confirmado.",
            "xss": "Reflexão ou padrões estáticos não provam execução no browser; nenhum script é executado para confirmação.",
        }
        return limitations.get(
            family,
            "A regra não constitui prova de cobertura nem confirmação de vulnerabilidade.",
        )

    @staticmethod
    def _verification_playbook_for(finding: Dict[str, Any]) -> Dict[str, Any]:
        title = str(finding.get("title", "")).lower()
        category = str(finding.get("category", "")).lower()
        scanner = str(finding.get("scanner", "")).lower()
        identity = f"{scanner} {title} {category}"

        if any(term in identity for term in (
            "endpoint discovery", "parameter discovery", "technology fingerprint",
            "robots/sitemap", "subdomain discovery", "hidden-file discovery",
            "javascript endpoint", "api discovery", "sensitive route discovery",
        )):
            return {
                "assessment_type": "Observação de reconhecimento; não é, por si só, uma vulnerabilidade.",
                "tools": "Navegador e DevTools; curl.exe ou PowerShell Invoke-WebRequest para leitura manual.",
                "steps": [
                    "Abra o endpoint indicado no navegador ou faça um pedido GET/HEAD autorizado.",
                    "Confirme que a rota ou tecnologia está realmente exposta e pertence ao âmbito aprovado.",
                    "Avalie a sensibilidade e a exposição com o proprietário do sistema; não infira impacto apenas pelo nome da rota.",
                ],
                "confirmation_criteria": "Registe como observação. Só classifique como vulnerabilidade se demonstrar exposição de dados/funcionalidade não pública e impacto concreto, sem aceder a dados reais de terceiros.",
                "false_positive_checks": "A rota pode ser pública intencionalmente, um erro genérico, conteúdo de exemplo ou uma identificação tecnológica imprecisa.",
            }

        if any(term in identity for term in (
            "sql injection", "sqli", "nosql", "command injection",
            "template injection", "ssti", "ldap injection", "xpath",
            "expression-language", "header injection", "category: injection",
        )):
            return {
                "assessment_type": "Indicador de possível injeção; não confirmado.",
                "tools": "OWASP ZAP em modo passivo e Burp Suite Community Repeater, manualmente em staging autorizado. Não usar automação de exploração.",
                "steps": [
                    "Repita primeiro o pedido original e guarde uma resposta de referência, sem alterar dados.",
                    "Em staging com cópia de segurança, varie apenas a entrada indicada usando um valor benigno e inerte, aprovado pelo responsável.",
                    "Compare resposta, estado e logs da aplicação com a referência; peça revisão do código/consultas ao responsável.",
                    "Não tente ler, alterar ou apagar dados, executar comandos, nem contornar autenticação.",
                ],
                "confirmation_criteria": "Exija um efeito causal, repetível e específico da entrada, corroborado por logs ou revisão de código. Mensagens de erro, reflexão ou pontuação do scanner, isoladamente, não confirmam injeção.",
                "false_positive_checks": "Compare respostas normais de validação, páginas de erro genéricas, diferenças de conteúdo dinâmico e comportamento do proxy/cache.",
            }

        if "open redirect" in identity:
            return {
                "assessment_type": "Indicador de possível redirecionamento externo; não confirmado.",
                "tools": "Burp Suite Community Repeater ou DevTools do Chrome/Edge para inspecionar a resposta, apenas em staging autorizado.",
                "steps": [
                    "Compare o pedido de referência com um pedido que use um destino de teste sob seu controle, apenas em staging autorizado.",
                    "Inspecione o estado HTTP e o cabeçalho Location; não siga o redirecionamento nem use destinos de terceiros.",
                    "Peça ao responsável para confirmar se o destino é validado por uma lista permitida e se existe impacto no fluxo real.",
                ],
                "confirmation_criteria": "Confirme apenas se a aplicação aceitar de forma reproduzível um destino externo não permitido e o responsável validar o impacto no contexto do serviço. Um parâmetro ou cabeçalho Location isolado não prova impacto.",
                "false_positive_checks": "Considere destinos relativos, domínios permitidos, páginas intermediárias de aviso e parâmetros que não controlam efetivamente o destino.",
            }

        if any(term in identity for term in (
            "xss", "cross-site scripting", "html injection", "content injection",
            "clickjacking", "prototype pollution", "client-side",
        )):
            return {
                "assessment_type": "Indicador de possível problema no navegador; não confirmado.",
                "tools": "OWASP ZAP passivo e DevTools do Chrome/Edge (Network, Elements e Console); Burp Repeater apenas para pedidos autorizados.",
                "steps": [
                    "Inspecione no separador Network o pedido, a resposta e o contexto exato do valor indicado.",
                    "Use apenas marcadores de texto inertes para verificar o fluxo e a codificação; isso não confirma execução de XSS.",
                    "Uma prova de execução de XSS só deve ser feita por pessoa qualificada em staging isolado e com autorização explícita; nunca a faça num site de produção.",
                    "Verifique no DOM como o valor é codificado e reveja as políticas de segurança aplicáveis com o responsável.",
                    "Para proteção contra framing, reveja os cabeçalhos e a política esperada com o proprietário da aplicação.",
                ],
                "confirmation_criteria": "Para XSS, reflexão ou marcador inerte não bastam: sem uma prova de execução controlada e autorizada em staging, mantenha como não confirmado. Para outros problemas de browser, exija comportamento reproduzível e impacto contrário à política documentada.",
                "false_positive_checks": "Texto refletido mas codificado, conteúdo inserido como texto, código morto, redirecionamento apenas previsto ou cabeçalho compensatório podem não ser exploráveis.",
            }

        if any(term in identity for term in (
            "access control", "idor", "bola", "privilege escalation",
            "authorization", "authorization", "function-level", "method access",
            "autorização", "controlo de acesso",
        )):
            return {
                "assessment_type": "Indicador de possível falha de autorização; não confirmado.",
                "tools": "Duas contas de teste autorizadas com permissões distintas e Burp Repeater ou OWASP ZAP manual request editor.",
                "steps": [
                    "Em staging, escolha duas contas de teste e registe qual recurso cada uma pode ler legitimamente.",
                    "Repita apenas pedidos GET de leitura, alternando as sessões de teste; não use IDs nem dados de utilizadores reais.",
                    "Compare a resposta com a matriz de autorização aprovada e peça ao proprietário para rever a decisão no servidor.",
                    "Pare se o pedido puder alterar estado ou se surgir informação real não pertencente às contas de teste.",
                ],
                "confirmation_criteria": "Confirme só quando uma conta de teste recebe, de forma repetível, dados ou uma capacidade fora da sua autorização documentada.",
                "false_positive_checks": "Recursos públicos, contas com permissões equivalentes, cache partilhada ou respostas 200 sem conteúdo protegido não demonstram por si só uma falha.",
            }

        if any(term in identity for term in (
            "authentication", "session", "cookie", "csrf", "password",
            "account enumeration", "login", "reset",
        )):
            return {
                "assessment_type": "Indicador de autenticação/sessão; não confirmado.",
                "tools": "DevTools do browser (Network/Application), OWASP ZAP passivo e contas descartáveis em staging.",
                "steps": [
                    "Use contas descartáveis e observe cookies, cabeçalhos e fluxo de login/logout no browser.",
                    "Compare o comportamento com a política de autenticação e sessão definida pelo responsável.",
                    "Para logout/expiração, confirme apenas com a própria sessão de teste e pedidos de leitura.",
                    "Não tente enumerar contas reais, redefinir palavras-passe de terceiros nem provocar bloqueios.",
                ],
                "confirmation_criteria": "Exija uma violação reproduzível da política aprovada (por exemplo, sessão de teste ainda válida após o evento de invalidação esperado), confirmada sem afetar outras contas.",
                "false_positive_checks": "Considere proxies, sessões persistentes intencionais, configuração específica do ambiente e políticas de cookie definidas por outro componente.",
            }

        if any(term in identity for term in (
            "csp", "cors", "security header", "server header", "cache-control",
            "tls", "mixed content", "directory listing", "source-map",
            "debug/development", "configuration", "information disclosure",
        )):
            return {
                "assessment_type": "Observação de configuração; impacto não confirmado.",
                "tools": "DevTools do Chrome/Edge (Network) e OWASP ZAP passivo; curl.exe -I para inspecionar cabeçalhos.",
                "steps": [
                    "Repita um pedido GET/HEAD autorizado e registe a resposta, o protocolo e o contexto de utilização.",
                    "Compare a configuração observada com a política de segurança documentada pelo proprietário.",
                    "Verifique se outro cabeçalho, proxy ou controlo compensatório altera o risco antes de classificar o resultado.",
                ],
                "confirmation_criteria": "Confirme apenas uma divergência real da política que tenha impacto demonstrável no contexto da aplicação; a ausência de um cabeçalho não prova, isoladamente, exploração.",
                "false_positive_checks": "Considere cabeçalhos injetados por proxy/CDN, rotas públicas, conteúdo estático e controlos compensatórios aplicados noutro componente.",
            }

        if any(term in identity for term in (
            "api /", "graphql", "websocket", "mass assignment",
            "data exposure", "rest api", "http method",
        )):
            return {
                "assessment_type": "Indicador de configuração/API; não confirmado.",
                "tools": "OWASP ZAP passivo, Burp Suite Repeater e especificação OpenAPI/GraphQL autorizada.",
                "steps": [
                    "Compare o endpoint e a resposta com a especificação e a matriz de acesso aprovadas.",
                    "Use apenas operações GET/read-only e contas de teste; não envie campos de escrita nem mutações.",
                    "Peça ao responsável pela API para confirmar se os campos e métodos observados são intencionais.",
                ],
                "confirmation_criteria": "Confirme apenas uma divergência reproduzível que exponha dados de teste não autorizados ou viole uma política documentada.",
                "false_positive_checks": "Documentação desatualizada, endpoints públicos, campos esperados e respostas de erro podem parecer exposição sem impacto.",
            }

        if any(term in identity for term in (
            "ssrf", "path traversal", "local-file", "xxe", "file upload",
            "server-side", "command execution",
        )):
            return {
                "assessment_type": "Indicador de comportamento server-side; não confirmado.",
                "tools": "OWASP ZAP passivo, logs da aplicação e um endpoint de teste controlado pelo responsável em staging.",
                "steps": [
                    "Não teste contra metadados cloud, endereços internos, ficheiros do sistema ou serviços de terceiros.",
                    "Peça ao responsável para observar, em staging, os logs da aplicação e uma origem de teste isolada e autorizada.",
                    "Use somente leitura e entradas benignas previamente aprovadas; não carregue ficheiros executáveis nem tente ler ficheiros.",
                    "Correlacione o pedido com os logs do servidor e com o comportamento esperado documentado.",
                ],
                "confirmation_criteria": "Exija evidência correlacionada de que a entrada causou acesso server-side não previsto em recurso de teste controlado, sem recolher conteúdo sensível.",
                "false_positive_checks": "Mensagens genéricas, proxy/cache, validação local, simulações e respostas estáticas não demonstram acesso server-side.",
            }

        return {
            "assessment_type": "Indicador heurístico não confirmado.",
            "tools": "OWASP ZAP passivo e DevTools do browser; peça revisão ao responsável pelo componente.",
            "steps": [
                "Repita apenas o pedido indicado no ambiente autorizado e compare com uma resposta de referência.",
                "Inspecione a evidência apresentada e a configuração/código relevante com o responsável.",
                "Não execute ações de escrita, aceda a dados de terceiros nem use payloads não aprovados.",
            ],
            "confirmation_criteria": "Confirme apenas um comportamento reproduzível com impacto concreto e fora da política autorizada.",
            "false_positive_checks": "Avalie respostas dinâmicas, conteúdo público, diferenças de ambiente e controlos compensatórios.",
        }

    @staticmethod
    def _verification_tool_for(finding: Dict[str, Any]) -> str:
        return ScanManager._verification_playbook_for(finding)["tools"]

    @staticmethod
    def _impact_in_portuguese(finding: Dict[str, Any]) -> str:
        impact = str(finding.get("impact", "") or "").strip()
        if impact:
            return impact
        title = str(finding.get("title", "") or "")
        if "XSS" in title:
            return "Um atacante pode executar scripts no navegador da vítima, roubar sessão ou manipular a página para capturar dados do utilizador."
        if "SQL" in title or "SQLi" in title:
            return "Um atacante pode ler, alterar ou remover dados sensíveis da base de dados, e em cenários graves também pode contornar regras de acesso."
        if "SSRF" in title:
            return "Um atacante pode forçar o servidor a aceder a recursos internos ou externos não previstos, expondo serviços internos ou dados sensíveis."
        if "CSRF" in title:
            return "Um atacante pode forçar ações autenticadas sem o consentimento do utilizador, como alterar dados ou operações críticas."
        if "CORS" in title:
            return "Um atacante pode abusar da política de origem cruzada para obter dados sensíveis em contextos não autorizados."
        return "A falha pode permitir acesso não autorizado, manipulação de dados, fuga de informação ou abuso de sessões e recursos do sistema."

    @staticmethod
    def _extract_form_values(html: str) -> Dict[str, str]:
        if not html:
            return {}
        parser = SimpleHTMLLinkParser()
        parser.feed(html)
        if not parser.forms:
            return {}
        return {
            str(field["name"]): str(field.get("value", ""))
            for field in parser.forms[0]["inputs"]
            if field.get("name") and field.get("type", "").lower() == "hidden"
        }

    @staticmethod
    def _extract_login_form(html: str) -> Optional[dict]:
        if not html:
            return None
        parser = SimpleHTMLLinkParser()
        parser.feed(html)
        return next(
            (form for form in parser.forms if form.get("method", "get").lower() == "post"),
            None,
        )

    @staticmethod
    def _extract_form_action(html: str) -> Optional[str]:
        if not html:
            return None
        parser = SimpleHTMLLinkParser()
        parser.feed(html)
        return parser.forms[0].get("action") if parser.forms else None

    @staticmethod
    async def authenticate_session(
        session: aiohttp.ClientSession,
        auth: Optional[AuthWorkflowConfig],
        username: Optional[str],
        password: Optional[str],
        base_url: Optional[str] = None,
        scope: Optional[TargetScope] = None,
    ) -> Optional[dict]:
        if auth is None or not auth.is_configured():
            return None
        if not username or not password:
            return None
        if not auth.success_indicator:
            raise ValueError("A success indicator is required to verify the login.")

        login_url = str(auth.login_url).strip()
        if base_url and not login_url.startswith(("http://", "https://")):
            login_url = urljoin(base_url, login_url)
        if scope is not None and not scope.is_in_scope(login_url):
            raise ValueError("The login URL must remain inside the authorized scope.")

        async with session.get(login_url, allow_redirects=True, timeout=15) as response:
            if not 200 <= response.status < 300:
                raise ValueError("The login page did not return a successful response.")
            login_page_url = str(response.url)
            body = await read_response_body(response)

        form = ScanManager._extract_login_form(body)
        if form is None:
            raise ValueError("No POST login form was found; credentials were not submitted.")
        field_names = {
            str(field.get("name"))
            for field in form.get("inputs", [])
            if field.get("name")
        }
        if (
            auth.username_field not in field_names
            or auth.password_field not in field_names
        ):
            raise ValueError("Configured credential fields were not present in the login form.")

        form_values = {
            str(field["name"]): str(field.get("value", ""))
            for field in form.get("inputs", [])
            if field.get("name") and field.get("type", "").lower() == "hidden"
        }
        payload = auth.to_login_payload(username, password, form_values)

        form_action = form.get("action")
        action_url = (
            urljoin(login_page_url, form_action)
            if form_action
            else login_page_url
        )
        if scope is not None and not scope.is_in_scope(action_url):
            raise ValueError("The login form action must remain inside the authorized scope.")

        async with session.post(
            action_url,
            data=payload,
            allow_redirects=False,
            timeout=15,
        ) as response:
            login_status = response.status
            final_body = await read_response_body(response)
            location = response.headers.get("Location")

        if login_status in {301, 302, 303} and location:
            verification_url = urljoin(action_url, location)
            if scope is not None and not scope.is_in_scope(verification_url):
                raise ValueError("The post-login redirect must remain inside the authorized scope.")
            async with session.get(
                verification_url,
                allow_redirects=True,
                timeout=15,
            ) as response:
                status = response.status
                final_body = await read_response_body(response)
        else:
            status = login_status

        success = (
            200 <= status < 300
            and str(auth.success_indicator).lower() in final_body.lower()
        )
        return {
            "status": status,
            "success": success,
        }

    @staticmethod
    def _normalize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(finding, dict):
            return {}
        normalized = dict(finding)
        confidence = normalized.get("confidence", 0)
        try:
            normalized["confidence"] = int(confidence)
        except (TypeError, ValueError):
            normalized["confidence"] = 0
        normalized["status"] = str(normalized.get("status", "Potential")).strip() or "Potential"
        normalized["verification_status"] = "Requires manual verification"
        normalized["verification_playbook"] = ScanManager._verification_playbook_for(normalized)
        normalized["assessment_type"] = normalized["verification_playbook"]["assessment_type"]
        normalized["verification_tool"] = ScanManager._verification_tool_for(normalized)
        normalized["impact_pt"] = ScanManager._impact_in_portuguese(normalized)
        return normalized

    async def execute(
        self,
        endpoints: List[dict],
        progress: Optional[dict] = None,
        auth: Optional[AuthWorkflowConfig] = None,
        rate_limiter: Optional[RequestRateLimiter] = None,
        scope: Optional[TargetScope] = None,
        session: Optional[aiohttp.ClientSession] = None,
        passive_only: bool = False,
        auth_result: Optional[dict] = None,
    ) -> Dict[str, list]:
        self.findings = []
        errors = []
        self.errors = errors
        error_count = 0
        found_names = []
        scanner_coverage = []
        selected_scanners = [
            scanner
            for scanner in self.scanners
            if not passive_only or scanner.name in self.PASSIVE_SCANNER_NAMES
        ]
        all_names = [scanner.name for scanner in selected_scanners]
        fixture_covered = {
            "CSP Configuration",
            "Security headers",
            "Session Cookie Security",
            "Cache-control issues",
            "Clickjacking",
        }
        limiter = rate_limiter or RequestRateLimiter(2.0)
        async with AsyncExitStack() as stack:
            if session is None:
                session = await stack.enter_async_context(aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=15, connect=5, sock_read=10),
                    trace_configs=[rate_limit_trace_config(limiter, scope, progress)],
                ))
            for scanner in selected_scanners:
                if progress is not None:
                    progress["module"] = scanner.name
                module_findings = []
                scanner_record = {
                    "name": scanner.name,
                    "description": getattr(scanner, "description", ""),
                    "mode": (
                        "passive"
                        if scanner.name in self.PASSIVE_SCANNER_NAMES
                        else "active"
                    ),
                    "selected": True,
                    "wstg_alignment": self._wstg_alignment(scanner),
                    "what_is_not_verified": self._family_limitations(scanner),
                    "endpoints_considered": len(endpoints),
                    "applicable_endpoints": 0,
                    "not_applicable_endpoints": 0,
                    "checks_completed": 0,
                    "findings": 0,
                    "errors": 0,
                    "validation_status": (
                        "synthetic_fixtures_only"
                        if scanner.name in fixture_covered
                        else "not_independently_validated"
                    ),
                    "coverage_note": (
                        "A aplicabilidade reflete apenas a condição interna do scanner; "
                        "não prova cobertura completa."
                    ),
                }
                for endpoint in endpoints:
                    try:
                        if scanner.applicable(endpoint):
                            scanner_record["applicable_endpoints"] += 1
                            findings = await scanner.run(endpoint, session=session)
                            scanner_record["checks_completed"] += 1
                            for raw_finding in findings:
                                finding_with_scanner = dict(raw_finding)
                                finding_with_scanner["scanner"] = scanner.name
                                normalized = self._normalize_finding(finding_with_scanner)
                                if self.finding_validator.validate(normalized):
                                    module_findings.append(normalized)
                                    self.findings.append(normalized)
                                else:
                                    logger.warning(
                                        "Scanner %s returned an incomplete finding",
                                        scanner.name,
                                    )
                                    error_count += 1
                                    scanner_record["errors"] += 1
                                    if len(errors) < 100:
                                        errors.append({
                                            "stage": "testing",
                                            "component": scanner.name,
                                            "error_type": "InvalidFinding",
                                        })
                                    if progress is not None:
                                        progress["error_count"] = (
                                            progress.get("error_count", 0) + 1
                                        )
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        logger.warning(
                            "Scanner %s failed (%s)", scanner.name, type(exc).__name__
                        )
                        error_count += 1
                        scanner_record["errors"] += 1
                        if len(errors) < 100:
                            errors.append({
                                "stage": "testing",
                                "component": scanner.name,
                                "error_type": type(exc).__name__,
                            })
                        if progress is not None:
                            progress["error_count"] = progress.get("error_count", 0) + 1
                    if progress is not None:
                        progress["tests_performed"] = (
                            progress.get("tests_performed", 0) + 1
                        )
                scanner_record["findings"] = len(module_findings)
                scanner_record["not_applicable_endpoints"] = (
                    len(endpoints) - scanner_record["applicable_endpoints"]
                )
                scanner_coverage.append(scanner_record)
                if module_findings:
                    found_names.append(scanner.name)
        selected_names = {scanner.name for scanner in selected_scanners}
        for scanner in self.scanners:
            if scanner.name in selected_names:
                continue
            scanner_coverage.append({
                "name": scanner.name,
                "description": getattr(scanner, "description", ""),
                "mode": (
                    "passive"
                    if scanner.name in self.PASSIVE_SCANNER_NAMES
                    else "active"
                ),
                "selected": False,
                "exclusion_reason": (
                    "Excluded by the selected passive-only scan mode."
                    if passive_only
                    else "Not selected by the current scan mode."
                ),
                "wstg_alignment": self._wstg_alignment(scanner),
                "what_is_not_verified": self._family_limitations(scanner),
                "endpoints_considered": len(endpoints),
                "applicable_endpoints": None,
                "not_applicable_endpoints": None,
                "checks_completed": 0,
                "findings": 0,
                "errors": 0,
                "validation_status": (
                    "synthetic_fixtures_only"
                    if scanner.name in fixture_covered
                    else "not_independently_validated"
                ),
                "coverage_note": "Scanner não executado nesta varredura.",
            })
        summary = {
            "scanners": all_names,
            "available_scanners": [scanner.name for scanner in self.scanners],
            "mode": "passive_only" if passive_only else "full",
            "found": found_names,
            "no_findings_returned": [name for name in all_names if name not in found_names],
            "findings_count": len(self.findings),
            "error_count": error_count,
            "scanner_coverage": scanner_coverage,
        }
        return {
            "findings": self.findings,
            "summary": summary,
            "errors": errors,
            "error_count": error_count,
            "auth": {
                "configured": auth is not None and auth.is_configured(),
                "success": auth_result.get("success") if auth_result else None,
                "status": auth_result.get("status") if auth_result else None,
            },
        }
