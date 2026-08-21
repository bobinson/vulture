"""Feature 0070 P7 — configuration_check detection backlog (group `configuration`).

Nine reviewed items land here. Every rule below carries at least one positive
and one *clean twin* that differs minimally — the twin is what proves the
predicate keys on the weakness and not on the surrounding vocabulary.

  CWE-757  algorithm downgrade      re-tag of the TLS version-token row
                                    (was CWE-326); `TLSv1.2` and
                                    `PROTOCOL_TLSv1_2` are the twins that the
                                    `(?![.\\d])` + `\\b` pair must reject.
  CWE-1021 frame protection off     helmet/Spring/Django frame switches and a
                                    CSP `frame-ancestors *`; a
                                    `frame-ancestors *.partner.example.com`
                                    allowlist is a RESTRICTION, not an opening.
  CWE-489  active debug code        eight statement-anchored breakpoint forms,
                                    with `#if DEBUG` and env-gate carve-outs.
  CWE-756  missing custom error     ASP.NET `customErrors mode="Off"`.
  CWE-5    J2EE cleartext transport a `<security-constraint>` that protects a
                                    named role but names no transport
                                    guarantee. A deny-all block (role-less
                                    `<auth-constraint>`) is the standard way to
                                    block a URL outright and is NOT a finding.
  CWE-11   ASP.NET debug binary     `<compilation debug="true">` under
                                    `<system.web>`, plus a Release
                                    `PropertyGroup` that turns optimisation off
                                    or defines DEBUG. `<DebugType>portable` is
                                    the Release DEFAULT and is never flagged.
  CWE-444  request smuggling        `insecureHTTPParser` / the CLI switch.
  CWE-926  Android component export `exported="true"` with no permission; the
                                    launcher activity (MAIN *or* LAUNCHER, OR
                                    never AND) is not a finding.
  CWE-426  untrusted search path    sudoers `Defaults env_keep`/`!env_reset`
                                    for a loader variable, vetoed by
                                    `secure_path=`.
"""

import tempfile
from pathlib import Path

from cwe_agent.skills.configuration_check import check_configuration


def _run(files: dict[str, str]) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return check_configuration(str(root))["findings"]


def _of(findings: list[dict], cwe: str) -> list[dict]:
    return [f for f in findings if f["category"] == f"CWE-{cwe}"]


# ------------------------------------------------------------------ CWE-757


def test_tls_version_downgrade_is_757_not_326() -> None:
    findings = _run({"app.py": """
def make_ctx():
    ssl_minimum_version = 'TLSv1'
    return ssl_minimum_version
"""})
    rows = _of(findings, "757")
    assert len(rows) == 1, findings
    assert rows[0]["line_start"] == 3
    # The row MOVED: configuration_check must no longer claim CWE-326 here
    # (326 stays reachable through crypto_check's key-size path).
    assert _of(findings, "326") == []


def test_sslv3_minimum_is_still_reported() -> None:
    findings = _run({"tls.js": """
const opts = { ssl: { minVersion: 'SSLv3' } }
"""})
    assert len(_of(findings, "757")) == 1, findings


def test_tls12_minimum_is_clean() -> None:
    """Clean twin: the same line with a SAFE version token."""
    findings = _run({"tls.js": """
const opts = { ssl: { minVersion: 'TLSv1.2' } }
"""})
    assert _of(findings, "757") == []


def test_protocol_tlsv1_2_constant_is_clean() -> None:
    """`_2` is a word char, so the trailing \\b rejects the hardened constant."""
    findings = _run({"tls.py": """
def ctx():
    ssl_min_version = ssl.PROTOCOL_TLSv1_2
    return ssl_min_version
"""})
    assert _of(findings, "757") == []


# ----------------------------------------------------------------- CWE-1021


def test_frameguard_disabled_is_flagged() -> None:
    findings = _run({"server.js": """
function boot (app) {
  app.use(helmet({ frameguard: false }))
}
"""})
    rows = _of(findings, "1021")
    assert len(rows) == 1, findings
    assert rows[0]["check_id"] == "cwe.configuration.frame_protection"


def test_csp_frame_ancestors_wildcard_is_flagged() -> None:
    findings = _run({"csp.js": """
function policy (res) {
  res.setHeader('Content-Security-Policy', "frame-ancestors *; default-src 'self'")
}
"""})
    assert len(_of(findings, "1021")) == 1, findings


def test_frame_ancestors_subdomain_allowlist_is_clean() -> None:
    """Clean twin: `*` as a subdomain wildcard is a restriction, not an opening."""
    findings = _run({"csp.js": """
function policy (res) {
  res.setHeader('Content-Security-Policy', "frame-ancestors *.partner.example.com")
}
"""})
    assert _of(findings, "1021") == []


def test_frame_ancestors_none_is_clean() -> None:
    findings = _run({"csp.js": """
function policy (res) {
  res.setHeader('Content-Security-Policy', "frame-ancestors 'none'")
}
"""})
    assert _of(findings, "1021") == []


def test_report_only_frame_ancestors_wildcard_is_clean() -> None:
    """A report-only policy enforces nothing, so it removes no protection."""
    findings = _run({"csp.js": """
function policy (res) {
  res.setHeader('Content-Security-Policy-Report-Only', "frame-ancestors *;")
}
"""})
    assert _of(findings, "1021") == []


def test_allowall_header_is_one_1021_row() -> None:
    """Row-stacking invariant: the ALLOWALL line must not emit twice."""
    findings = _run({"headers.conf": """
add_header X-Frame-Options ALLOWALL;
"""})
    assert len(_of(findings, "1021")) == 1, findings


def test_frame_protection_is_one_row_per_file() -> None:
    findings = _run({"server.js": """
function boot (app) {
  app.use(helmet({ frameguard: false }))
  app.use(helmet({ xFrameOptions: false }))
}
"""})
    rows = _of(findings, "1021")
    assert len(rows) == 1, rows
    assert rows[0]["line_start"] == 3
    assert rows[0]["line_end"] == 4


def test_allow_from_is_a_separate_low_row() -> None:
    findings = _run({"headers.conf": """
add_header X-Frame-Options "ALLOW-FROM https://partner.example.com";
"""})
    rows = _of(findings, "1021")
    assert len(rows) == 1, rows
    assert rows[0]["severity"] == "low"
    assert rows[0]["check_id"] == "cwe.configuration.frame_allow_from"


def test_allow_from_with_csp_frame_ancestors_is_clean() -> None:
    """ALLOW-FROM is legacy fallback when a CSP already restricts framing."""
    findings = _run({"headers.conf": """
add_header Content-Security-Policy "frame-ancestors 'self'";
add_header X-Frame-Options "ALLOW-FROM https://partner.example.com";
"""})
    assert _of(findings, "1021") == []


def test_spring_frame_options_disable_is_flagged() -> None:
    findings = _run({"SecurityConfig.java": """
public void configure(HttpSecurity http) throws Exception {
    http.headers().frameOptions().disable();
}
"""})
    assert len(_of(findings, "1021")) == 1, findings


def test_django_xframe_exempt_is_flagged() -> None:
    findings = _run({"views.py": """
@xframe_options_exempt
def widget(request):
    return render(request, 'widget.html')
"""})
    assert len(_of(findings, "1021")) == 1, findings


# ------------------------------------------------------------------ CWE-489


def test_js_debugger_statement_is_flagged() -> None:
    findings = _run({"Panel.tsx": """
export function Panel () {
  debugger;
  return null
}
"""})
    rows = _of(findings, "489")
    assert len(rows) == 1, findings
    assert rows[0]["line_start"] == 3
    assert rows[0]["check_id"] == "cwe.configuration.active_debug_code"
    # One row, not two: the sibling debug-config patterns must not also claim it.
    assert len(findings) == 1, findings


def test_python_set_trace_is_flagged() -> None:
    findings = _run({"handler.py": """
def handle(req):
    import pdb; pdb.set_trace()
    return req
"""})
    assert len(_of(findings, "489")) == 1, findings


def test_dotnet_debugger_launch_is_flagged() -> None:
    findings = _run({"Startup.cs": """
public void Configure() {
    Debugger.Launch();
}
"""})
    assert len(_of(findings, "489")) == 1, findings


def test_php_xdebug_break_is_flagged() -> None:
    findings = _run({"index.php": """
function render($tpl) {
    xdebug_break();
    return $tpl;
}
"""})
    assert len(_of(findings, "489")) == 1, findings


def test_ruby_binding_pry_is_flagged() -> None:
    findings = _run({"app.rb": """
def show
  binding.pry
end
"""})
    assert len(_of(findings, "489")) == 1, findings


def test_go_runtime_breakpoint_is_flagged() -> None:
    findings = _run({"main.go": """
func serve() {
	runtime.Breakpoint()
}
"""})
    assert len(_of(findings, "489")) == 1, findings


def test_debugger_as_config_value_is_clean() -> None:
    """Clean twin: a lint-rule entry names `debugger`, it does not break."""
    findings = _run({"eslintrc.json": """
{
  "rules": { "no-debugger": "error", "debugger": "off" }
}
"""})
    assert _of(findings, "489") == []


def test_commented_out_debugger_is_clean() -> None:
    findings = _run({"Panel.tsx": """
export function Panel () {
  // debugger;
  return null
}
"""})
    assert _of(findings, "489") == []


def test_debugger_launch_inside_if_debug_region_is_clean() -> None:
    """Compiled out of Release builds — not shipped debug code."""
    findings = _run({"Startup.cs": """
public void Configure() {
#if DEBUG
    Debugger.Launch();
#endif
}
"""})
    assert _of(findings, "489") == []


def test_debugger_launch_after_closed_debug_region_is_flagged() -> None:
    """The `#endif` closes the region, so the call IS in the Release build."""
    findings = _run({"Startup.cs": """
public void Configure() {
#if DEBUG
    Log("dev");
#endif
    Debugger.Launch();
}
"""})
    assert len(_of(findings, "489")) == 1, findings


def test_env_gated_breakpoint_is_clean() -> None:
    findings = _run({"handler.py": """
def handle(req):
    if os.getenv("PDB_ON_ERROR"):
        breakpoint()
    return req
"""})
    assert _of(findings, "489") == []


# ------------------------------------------------------------------ CWE-756


def test_custom_errors_off_is_flagged() -> None:
    findings = _run({"web.config": """
<configuration>
  <system.web>
    <customErrors mode="Off" />
  </system.web>
</configuration>
"""})
    rows = _of(findings, "756")
    assert len(rows) == 1, findings
    assert rows[0]["line_start"] == 4
    assert rows[0]["check_id"] == "cwe.configuration.missing_custom_error_page"


def test_http_errors_detailed_is_flagged_attribute_order_insensitive() -> None:
    findings = _run({"web.config": """
<configuration>
  <system.webServer>
    <httpErrors existingResponse="PassThrough" errorMode="Detailed">
    </httpErrors>
  </system.webServer>
</configuration>
"""})
    assert len(_of(findings, "756")) == 1, findings


def test_custom_errors_remote_only_is_clean() -> None:
    findings = _run({"web.config": """
<configuration>
  <system.web>
    <customErrors mode="RemoteOnly" defaultRedirect="~/Error" />
  </system.web>
</configuration>
"""})
    assert _of(findings, "756") == []


def test_commented_out_custom_errors_block_is_clean() -> None:
    """A multi-line XML comment is not a per-line comment marker."""
    findings = _run({"web.config": """
<configuration>
  <system.web>
    <!--
    <customErrors mode="Off" />
    -->
  </system.web>
</configuration>
"""})
    assert _of(findings, "756") == []


def test_xdt_transform_removal_is_clean() -> None:
    findings = _run({"web.release.config": """
<configuration xmlns:xdt="http://schemas.microsoft.com/XML-Document-Transform">
  <system.web>
    <customErrors mode="Off" xdt:Transform="RemoveAttributes(mode)" />
  </system.web>
</configuration>
"""})
    assert _of(findings, "756") == []


# -------------------------------------------------------------------- CWE-5


_WEB_XML_HEAD = '<web-app xmlns="http://java.sun.com/xml/ns/javaee" version="3.0">'


def test_role_protected_constraint_without_transport_guarantee_is_flagged() -> None:
    findings = _run({"web.xml": f"""
{_WEB_XML_HEAD}
  <security-constraint>
    <web-resource-collection>
      <url-pattern>/admin/*</url-pattern>
    </web-resource-collection>
    <auth-constraint>
      <role-name>admin</role-name>
    </auth-constraint>
  </security-constraint>
</web-app>
"""})
    rows = _of(findings, "5")
    assert len(rows) == 1, findings
    assert "/admin/*" in rows[0]["description"]
    # The load-balancer case must be named, or the recommendation is wrong
    # advice for the dominant modern deployment.
    assert "TLS terminates" in rows[0]["recommendation"]


def test_confidential_transport_guarantee_is_clean() -> None:
    findings = _run({"web.xml": f"""
{_WEB_XML_HEAD}
  <security-constraint>
    <web-resource-collection>
      <url-pattern>/admin/*</url-pattern>
    </web-resource-collection>
    <auth-constraint>
      <role-name>admin</role-name>
    </auth-constraint>
    <user-data-constraint>
      <transport-guarantee>CONFIDENTIAL</transport-guarantee>
    </user-data-constraint>
  </security-constraint>
</web-app>
"""})
    assert _of(findings, "5") == []


def test_deny_all_constraint_is_clean() -> None:
    """A role-less `<auth-constraint/>` blocks the URL outright: no credential
    ever crosses that wire, so a transport guarantee is meaningless."""
    findings = _run({"web.xml": f"""
{_WEB_XML_HEAD}
  <security-constraint>
    <web-resource-collection>
      <url-pattern>/WEB-INF/*</url-pattern>
    </web-resource-collection>
    <auth-constraint/>
  </security-constraint>
</web-app>
"""})
    assert _of(findings, "5") == []


def test_unauthenticated_constraint_is_clean() -> None:
    findings = _run({"web.xml": f"""
{_WEB_XML_HEAD}
  <security-constraint>
    <web-resource-collection>
      <url-pattern>/public/*</url-pattern>
    </web-resource-collection>
  </security-constraint>
</web-app>
"""})
    assert _of(findings, "5") == []


def test_commented_out_security_constraint_is_clean() -> None:
    findings = _run({"web.xml": f"""
{_WEB_XML_HEAD}
  <!--
  <security-constraint>
    <web-resource-collection>
      <url-pattern>/admin/*</url-pattern>
    </web-resource-collection>
    <auth-constraint>
      <role-name>admin</role-name>
    </auth-constraint>
  </security-constraint>
  -->
</web-app>
"""})
    assert _of(findings, "5") == []


def test_repeated_url_pattern_is_deduped() -> None:
    findings = _run({"web.xml": f"""
{_WEB_XML_HEAD}
  <security-constraint>
    <web-resource-collection>
      <url-pattern>/admin/*</url-pattern>
    </web-resource-collection>
    <auth-constraint><role-name>admin</role-name></auth-constraint>
  </security-constraint>
  <security-constraint>
    <web-resource-collection>
      <url-pattern>/admin/*</url-pattern>
      <http-method>POST</http-method>
    </web-resource-collection>
    <auth-constraint><role-name>admin</role-name></auth-constraint>
  </security-constraint>
</web-app>
"""})
    assert len(_of(findings, "5")) == 1, findings


# ------------------------------------------------------------------- CWE-11


def test_aspnet_compilation_debug_true_is_one_row() -> None:
    findings = _run({"web.config": """
<configuration>
  <system.web>
    <compilation debug="true" targetFramework="4.8" />
  </system.web>
</configuration>
"""})
    rows = _of(findings, "11")
    assert len(rows) == 1, findings
    assert rows[0]["line_start"] == 4
    # Row-stacking invariant: the pre-existing CWE-1188 `debug="true"` pattern
    # must not also claim this line.
    assert len(findings) == 1, findings


def test_nuget_config_debug_attribute_is_clean() -> None:
    """`<configuration>` is also nuget.config's root; the gate is `<system.web`."""
    findings = _run({"nuget.config": """
<configuration>
  <packageSources>
    <add key="local" value="./pkgs" debug="true" />
  </packageSources>
</configuration>
"""})
    assert _of(findings, "11") == []


def test_compilation_debug_false_is_clean() -> None:
    findings = _run({"web.config": """
<configuration>
  <system.web>
    <compilation debug="false" targetFramework="4.8" />
  </system.web>
</configuration>
"""})
    assert _of(findings, "11") == []


def test_release_property_group_with_optimize_off_is_flagged() -> None:
    findings = _run({"App.csproj": """
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup Condition="'$(Configuration)'=='Release'">
    <Optimize>false</Optimize>
  </PropertyGroup>
</Project>
"""})
    assert len(_of(findings, "11")) == 1, findings


def test_release_property_group_defining_debug_is_flagged() -> None:
    findings = _run({"App.csproj": """
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|AnyCPU'">
    <DefineConstants>TRACE;DEBUG</DefineConstants>
  </PropertyGroup>
</Project>
"""})
    assert len(_of(findings, "11")) == 1, findings


def test_release_portable_pdb_is_clean() -> None:
    """A portable PDB in Release is the SDK default and recommended practice."""
    findings = _run({"App.csproj": """
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup Condition="'$(Configuration)'=='Release'">
    <DebugType>portable</DebugType>
    <DebugSymbols>true</DebugSymbols>
    <Optimize>true</Optimize>
  </PropertyGroup>
</Project>
"""})
    assert _of(findings, "11") == []


def test_debug_property_group_with_optimize_off_is_clean() -> None:
    """Optimisation off in the Debug configuration is correct by definition."""
    findings = _run({"App.csproj": """
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup Condition="'$(Configuration)'=='Debug'">
    <Optimize>false</Optimize>
    <DefineConstants>TRACE;DEBUG</DefineConstants>
  </PropertyGroup>
</Project>
"""})
    assert _of(findings, "11") == []


# ------------------------------------------------------------------ CWE-444


def test_insecure_http_parser_option_is_flagged() -> None:
    findings = _run({"server.js": """
function boot () {
  return http.createServer({ insecureHTTPParser: true }, handler)
}
"""})
    rows = _of(findings, "444")
    assert len(rows) == 1, findings
    assert rows[0]["severity"] == "high"
    assert rows[0]["check_id"] == "cwe.configuration.insecure_http_parser"


def test_insecure_http_parser_cli_flag_is_flagged() -> None:
    findings = _run({"ci.yml": """
jobs:
  run:
    env:
      NODE_OPTIONS: --insecure-http-parser
"""})
    assert len(_of(findings, "444")) == 1, findings


def test_insecure_http_parser_false_is_clean() -> None:
    findings = _run({"server.js": """
function boot () {
  return http.createServer({ insecureHTTPParser: false }, handler)
}
"""})
    assert _of(findings, "444") == []


def test_insecure_http_parser_is_one_row_per_file() -> None:
    findings = _run({"server.ts": """
function boot () {
  const a = http.createServer({ insecureHTTPParser: true })
  const b = https.createServer({ insecureHTTPParser: true })
  return [a, b]
}
"""})
    assert len(_of(findings, "444")) == 1, findings


# ------------------------------------------------------------------ CWE-926


_MANIFEST_HEAD = (
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
    '    xmlns:tools="http://schemas.android.com/tools"\n'
    '    package="com.example.app">\n'
    "  <application>"
)
_MANIFEST_TAIL = "  </application>\n</manifest>"


def test_exported_provider_without_permission_is_flagged() -> None:
    findings = _run({"AndroidManifest.xml": f"""
{_MANIFEST_HEAD}
    <provider
        android:name=".data.NotesProvider"
        android:authorities="com.example.app.notes"
        android:grantUriPermissions="true"
        android:exported="true" />
{_MANIFEST_TAIL}
"""})
    rows = _of(findings, "926")
    assert len(rows) == 1, findings
    assert rows[0]["severity"] == "high"
    assert ".data.NotesProvider" in rows[0]["description"]


def test_exported_service_without_permission_is_medium() -> None:
    findings = _run({"AndroidManifest.xml": f"""
{_MANIFEST_HEAD}
    <service android:name=".sync.SyncService" android:exported="true" />
{_MANIFEST_TAIL}
"""})
    rows = _of(findings, "926")
    assert len(rows) == 1, findings
    assert rows[0]["severity"] == "medium"


def test_launcher_activity_is_clean() -> None:
    """The two-phase extractor must keep the LAUNCHER category INSIDE the body:
    a naive non-greedy `/>` block ends at the first self-closing child and
    reports the app entry point (measured 100% false on a real manifest)."""
    findings = _run({"AndroidManifest.xml": f"""
{_MANIFEST_HEAD}
    <activity
        android:name=".ui.MainActivity"
        android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
{_MANIFEST_TAIL}
"""})
    assert _of(findings, "926") == []


def test_exported_with_permission_is_clean() -> None:
    findings = _run({"AndroidManifest.xml": f"""
{_MANIFEST_HEAD}
    <receiver
        android:name=".push.PushReceiver"
        android:permission="com.example.app.permission.PUSH"
        android:exported="true" />
{_MANIFEST_TAIL}
"""})
    assert _of(findings, "926") == []


def test_exported_false_is_clean() -> None:
    findings = _run({"AndroidManifest.xml": f"""
{_MANIFEST_HEAD}
    <service android:name=".sync.SyncService" android:exported="false" />
{_MANIFEST_TAIL}
"""})
    assert _of(findings, "926") == []


def test_framework_contract_export_is_clean() -> None:
    """A TileService MUST be exported; the framework binds it by contract."""
    findings = _run({"AndroidManifest.xml": f"""
{_MANIFEST_HEAD}
    <service android:name=".qs.Tile" android:exported="true">
      <intent-filter>
        <action android:name="android.service.quicksettings.TileService" />
      </intent-filter>
    </service>
{_MANIFEST_TAIL}
"""})
    assert _of(findings, "926") == []


def test_tools_node_remove_is_clean() -> None:
    findings = _run({"AndroidManifest.xml": f"""
{_MANIFEST_HEAD}
    <provider
        android:name="androidx.startup.InitializationProvider"
        android:authorities="com.example.app.startup"
        android:exported="true"
        tools:node="remove" />
{_MANIFEST_TAIL}
"""})
    assert _of(findings, "926") == []


def test_non_android_xml_is_not_scanned_for_exports() -> None:
    """The file gate is content-keyed, not filename-keyed."""
    findings = _run({"pom.xml": """
<project>
  <build>
    <provider android:exported="true" />
  </build>
</project>
"""})
    assert _of(findings, "926") == []


# ------------------------------------------------------------------ CWE-426


def test_sudoers_env_keep_loader_variable_is_flagged() -> None:
    findings = _run({"sudoers.conf": """
Defaults env_reset
Defaults env_keep += "LD_LIBRARY_PATH LD_PRELOAD"
%wheel ALL=(ALL) ALL
"""})
    rows = _of(findings, "426")
    assert len(rows) == 1, findings
    assert rows[0]["line_start"] == 3
    assert rows[0]["check_id"] == "cwe.configuration.untrusted_search_path"


def test_sudoers_env_reset_disabled_is_flagged() -> None:
    findings = _run({"sudoers.conf": """
Defaults !env_reset
"""})
    assert len(_of(findings, "426")) == 1, findings


def test_sudoers_with_secure_path_is_clean() -> None:
    findings = _run({"sudoers.conf": """
Defaults secure_path="/usr/sbin:/usr/bin:/sbin:/bin"
Defaults env_keep += "PATH"
"""})
    assert _of(findings, "426") == []


def test_env_keep_named_by_hardening_code_is_clean() -> None:
    """Naming the variable while scrubbing it is not a directive."""
    findings = _run({"harden.py": """
def scrub(cfg):
    removed = ["env_keep", "LD_PRELOAD", "PYTHONPATH"]
    return [line for line in cfg if not any(r in line for r in removed)]
"""})
    assert _of(findings, "426") == []


def test_env_keep_of_non_loader_variable_is_clean() -> None:
    findings = _run({"sudoers.conf": """
Defaults env_keep += "EDITOR VISUAL"
"""})
    assert _of(findings, "426") == []
