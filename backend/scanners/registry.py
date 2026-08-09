from backend.scanners.injection.command_injection import CommandInjectionScanner
from backend.scanners.injection.expression_language_injection import ExpressionLanguageInjectionScanner
from backend.scanners.injection.header_injection import HeaderInjectionScanner
from backend.scanners.injection.ldap_injection import LdapInjectionScanner
from backend.scanners.injection.nosql_injection import NoSqlInjectionScanner
from backend.scanners.injection.ssti import SstiScanner
from backend.scanners.injection.sql_injection import SqlInjectionScanner
from backend.scanners.injection.xpath_injection import XPathInjectionScanner
from backend.scanners.xss.reflected_xss import ReflectedXssScanner
from backend.scanners.xss.html_injection import HtmlInjectionScanner
from backend.scanners.xss.open_redirect import OpenRedirectScanner
from backend.scanners.xss.stored_xss import StoredXssScanner
from backend.scanners.xss.dom_xss import DomXssScanner
from backend.scanners.xss.content_injection import ContentInjectionScanner
from backend.scanners.client_side.clickjacking import ClickjackingScanner
from backend.scanners.client_side.prototype_pollution import PrototypePollutionScanner
from backend.scanners.access_control.api_authorization import ApiAuthorizationInconsistencyScanner
from backend.scanners.access_control.idor_bola import IdorBolaScanner
from backend.scanners.access_control.function_level_auth import MissingFunctionLevelAuthorizationScanner
from backend.scanners.access_control.privilege_escalation import HorizontalPrivilegeEscalationScanner, VerticalPrivilegeEscalationScanner
from backend.scanners.access_control.sensitive_route import SensitiveRouteScanner
from backend.scanners.access_control.method_access_control import MethodAccessControlScanner
from backend.scanners.authentication.authentication_weakness import AuthenticationWeaknessScanner
from backend.scanners.authentication.account_enumeration import AccountEnumerationScanner
from backend.scanners.authentication.password_reset import PasswordResetWorkflowScanner
from backend.scanners.authentication.session_invalidation import SessionInvalidationScanner
from backend.scanners.authentication.session_management import SessionManagementWeaknessScanner
from backend.scanners.authentication.session_cookie import SessionCookieScanner
from backend.scanners.authentication.csrf_protection import CsrfProtectionScanner
from backend.scanners.api.excessive_data_exposure import ExcessiveDataExposureScanner
from backend.scanners.api.graphql_security import GraphQLSecurityScanner
from backend.scanners.api.http_method_issues import HttpMethodConfigurationScanner
from backend.scanners.api.mass_assignment import ApiMassAssignmentScanner
from backend.scanners.api.rest_api_security import RestApiSecurityScanner
from backend.scanners.api.websocket_security import WebSocketSecurityScanner
from backend.scanners.configuration.cache_control import CacheControlScanner
from backend.scanners.configuration.cors import CorsScanner
from backend.scanners.configuration.csp import CspScanner
from backend.scanners.configuration.debug_exposure import DebugExposureScanner
from backend.scanners.configuration.directory_listing import DirectoryListingScanner
from backend.scanners.configuration.mixed_content import MixedContentScanner
from backend.scanners.configuration.security_headers import SecurityHeadersScanner
from backend.scanners.configuration.source_map_exposure import SourceMapExposureScanner
from backend.scanners.configuration.tls import TlsSecurityScanner
from backend.scanners.disclosure.server_header import ServerHeaderScanner
from backend.scanners.recon.api_discovery import ApiDiscoveryScanner
from backend.scanners.recon.endpoint_discovery import EndpointDiscoveryScanner
from backend.scanners.recon.hidden_file_discovery import HiddenFileDiscoveryScanner
from backend.scanners.recon.javascript_endpoint_extraction import JavascriptEndpointExtractionScanner
from backend.scanners.recon.parameter_discovery import ParameterDiscoveryScanner
from backend.scanners.recon.subdomain_discovery import SubdomainDiscoveryScanner
from backend.scanners.recon.technology_fingerprinting import TechnologyFingerprintingScanner
from backend.scanners.recon.robots_sitemap import RobotsSitemapScanner
from backend.scanners.server_side.local_file_exposure import LocalFileExposureScanner
from backend.scanners.server_side.path_traversal import PathTraversalScanner
from backend.scanners.server_side.server_side_info_disclosure import ServerSideInformationDisclosureScanner
from backend.scanners.server_side.ssrf import SsrfScanner
from backend.scanners.server_side.unsafe_file_upload import UnsafeFileUploadScanner
from backend.scanners.server_side.xxe import XxeScanner


def all_scanners():
    return [
        SqlInjectionScanner(),
        NoSqlInjectionScanner(),
        CommandInjectionScanner(),
        SstiScanner(),
        LdapInjectionScanner(),
        XPathInjectionScanner(),
        ExpressionLanguageInjectionScanner(),
        HeaderInjectionScanner(),
        ReflectedXssScanner(),
        StoredXssScanner(),
        DomXssScanner(),
        HtmlInjectionScanner(),
        OpenRedirectScanner(),
        ContentInjectionScanner(),
        ClickjackingScanner(),
        PrototypePollutionScanner(),
        IdorBolaScanner(),
        HorizontalPrivilegeEscalationScanner(),
        VerticalPrivilegeEscalationScanner(),
        MissingFunctionLevelAuthorizationScanner(),
        ApiAuthorizationInconsistencyScanner(),
        SensitiveRouteScanner(),
        MethodAccessControlScanner(),
        AuthenticationWeaknessScanner(),
        SessionManagementWeaknessScanner(),
        SessionCookieScanner(),
        SessionInvalidationScanner(),
        PasswordResetWorkflowScanner(),
        AccountEnumerationScanner(),
        CsrfProtectionScanner(),
        RestApiSecurityScanner(),
        GraphQLSecurityScanner(),
        WebSocketSecurityScanner(),
        ApiMassAssignmentScanner(),
        ExcessiveDataExposureScanner(),
        HttpMethodConfigurationScanner(),
        CspScanner(),
        SecurityHeadersScanner(),
        TlsSecurityScanner(),
        CacheControlScanner(),
        MixedContentScanner(),
        DebugExposureScanner(),
        DirectoryListingScanner(),
        SourceMapExposureScanner(),
        ApiDiscoveryScanner(),
        EndpointDiscoveryScanner(),
        HiddenFileDiscoveryScanner(),
        JavascriptEndpointExtractionScanner(),
        ParameterDiscoveryScanner(),
        SubdomainDiscoveryScanner(),
        TechnologyFingerprintingScanner(),
        SsrfScanner(),
        PathTraversalScanner(),
        LocalFileExposureScanner(),
        UnsafeFileUploadScanner(),
        XxeScanner(),
        ServerSideInformationDisclosureScanner(),
        CorsScanner(),
        ServerHeaderScanner(),
        RobotsSitemapScanner(),
    ]
