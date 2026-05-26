import streamlit as st
import pandas as pd
import io
import sys
import re
import tempfile
import html as html_lib
from fpdf import FPDF, XPos, YPos
from wpaudit import WPAuditor
import plotly.express as px

st.set_page_config(page_title="WP Auditor GUI", page_icon="🛡️", layout="wide")

st.title("🛡️ WordPress Security Auditor")
st.markdown("Interfaz gráfica profesional para el escáner de seguridad de WordPress.")

st.sidebar.header("Configuración del Escáner")
target_url = st.sidebar.text_input("URL Objetivo", value="https://ejemplo.cl", help="Debe incluir http:// o https://")

delay = st.sidebar.number_input("Retraso (segundos)", min_value=0.0, max_value=10.0, value=0.0, step=0.1)
jitter = st.sidebar.number_input("Jitter (%)", min_value=0.0, max_value=100.0, value=0.0, step=1.0)

# Sincronizar hilos dinámicamente según delay
if delay > 0.0:
    threads = st.sidebar.slider("Hilos Concurrentes", min_value=1, max_value=50, value=1, disabled=True, help="Forzado a 1 porque se configuró un retraso (delay).")
else:
    threads = st.sidebar.slider("Hilos Concurrentes", min_value=1, max_value=50, value=5)

nvd_key = st.sidebar.text_input("NVD API Key (Opcional)", type="password", help="Evita bloqueos de límite de peticiones de la NIST")
verify_ssl = st.sidebar.checkbox("Verificar Certificados SSL (HTTPS)", value=False, help="Habilítalo para auditar la validez del certificado HTTPS")
output_csv = st.sidebar.text_input("Archivo de Exportación CSV", value="resultados.csv")
wordlist = st.sidebar.text_input("Ruta a Wordlist (Opcional)", value="")
req_timeout = st.sidebar.slider(
    "⏱️ Timeout HTTP (seg)",
    min_value=3, max_value=15, value=6,
    help="Tiempo máximo de espera por petición. Valores bajos = más rápido pero más falsos negativos en sitios lentos."
)

st.sidebar.subheader("Fases a Omitir")
skip_options = {
    "recon": "Reconocimiento e Inteligencia",
    "active_plugins": "Escaneo Activo de Plugins",
    "headers": "Cabeceras de Seguridad HTTP",
    "theme": "Detección Activa de Temas",
    "ports": "Escaneo de Puertos",
    "ssl_tls": "Auditoría Avanzada SSL/TLS",
    "xmlrpc": "Endpoint Sensibles (XML-RPC)",
    "rest": "REST API (Usuarios)",
    "author": "Enumeración de Autor",
    "login": "Enumeración de Login",
    "cron": "Pruebas wp-cron",
    "cli": "WP-CLI Config",
    "dir": "Directory Listing",
    "server_config": "Configuraciones del Servidor e Instaladores",
    "uploads": "Archivos Expuestos en Subidas",
    "classic": "Archivos Clásicos",
    "passive_malware": "Detección de Malware y Defacement",
    "routes": "Escaneo de Rutas"
}
skip_phases = st.sidebar.multiselect("Selecciona las fases que deseas saltar:", options=list(skip_options.keys()), format_func=lambda x: skip_options[x])

# UI Styles
st.markdown("""
<style>
.metric-card {
    background: linear-gradient(145deg, #1E3A8A, #0A2540);
    border-radius: 10px;
    padding: 15px;
    margin-bottom: 10px;
    border: 1px solid rgba(0, 243, 255, 0.2);
    border-left: 5px solid #00f3ff;
    box-shadow: 0 0 15px rgba(0, 243, 255, 0.15);
    transition: all 0.3s ease;
}
.metric-card:hover {
    box-shadow: 0 0 20px rgba(0, 243, 255, 0.3);
    transform: translateY(-2px);
    border: 1px solid rgba(0, 243, 255, 0.5);
    border-left: 5px solid #00f3ff;
}
.metric-card-title {
    font-size: 14px;
    color: #93C5FD;
    margin-bottom: 5px;
    text-transform: uppercase;
    letter-spacing: 1px;
}
.metric-card-value {
    font-size: 26px;
    font-weight: bold;
    color: #ffffff;
    text-shadow: 0 0 8px rgba(0, 243, 255, 0.4);
}
.finding-critical { border-left: 5px solid #ff0055; background-color: rgba(255, 0, 85, 0.1); padding: 10px; border-radius: 5px; margin: 5px 0; box-shadow: 0 0 10px rgba(255, 0, 85, 0.2); }
.finding-warning { border-left: 5px solid #ffcc00; background-color: rgba(255, 204, 0, 0.1); padding: 10px; border-radius: 5px; margin: 5px 0; box-shadow: 0 0 10px rgba(255, 204, 0, 0.2); }
.finding-info { border-left: 5px solid #00f3ff; background-color: rgba(0, 243, 255, 0.1); padding: 10px; border-radius: 5px; margin: 5px 0; box-shadow: 0 0 10px rgba(0, 243, 255, 0.2); }
.tech-summary {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 10px;
    margin: 8px 0 16px 0;
}
.tech-summary-item {
    border: 1px solid rgba(148, 163, 184, 0.28);
    background: rgba(15, 23, 42, 0.55);
    border-radius: 8px;
    padding: 10px 12px;
}
.tech-summary-label {
    color: #93C5FD;
    font-size: 12px;
    text-transform: uppercase;
}
.tech-summary-value {
    color: #ffffff;
    font-size: 24px;
    font-weight: 800;
}
.tech-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
    gap: 12px;
    margin-top: 8px;
}
.tech-card {
    min-height: 154px;
    border-radius: 8px;
    padding: 14px;
    border: 1px solid rgba(148, 163, 184, 0.26);
    background: linear-gradient(145deg, rgba(15, 23, 42, 0.92), rgba(30, 41, 59, 0.78));
    box-shadow: 0 8px 22px rgba(2, 6, 23, 0.22);
}
.tech-card-head {
    display: flex;
    align-items: center;
    gap: 12px;
}
.tech-icon, .tech-initial {
    width: 42px;
    height: 42px;
    border-radius: 8px;
    background: #ffffff;
    padding: 8px;
    object-fit: contain;
    flex: 0 0 auto;
}
.tech-initial {
    display: flex;
    align-items: center;
    justify-content: center;
    color: #0f172a;
    font-weight: 900;
    font-size: 20px;
}
.tech-name {
    color: #ffffff;
    font-weight: 800;
    font-size: 17px;
    line-height: 1.2;
    word-break: break-word;
}
.tech-category {
    color: #93C5FD;
    font-size: 12px;
    margin-top: 2px;
}
.tech-version {
    display: inline-block;
    margin-top: 8px;
    color: #dbeafe;
    background: rgba(59, 130, 246, 0.16);
    border: 1px solid rgba(96, 165, 250, 0.3);
    border-radius: 999px;
    padding: 2px 8px;
    font-size: 12px;
}
.tech-evidence {
    color: #cbd5e1;
    font-size: 12px;
    margin-top: 9px;
    line-height: 1.35;
}
.tech-confidence {
    margin-top: 10px;
    height: 7px;
    border-radius: 999px;
    background: rgba(148, 163, 184, 0.2);
    overflow: hidden;
}
.tech-confidence-fill {
    height: 100%;
    border-radius: 999px;
}
.tech-confidence-label {
    margin-top: 4px;
    color: #94a3b8;
    font-size: 11px;
}
</style>
""", unsafe_allow_html=True)

def strip_ansi(text):
    return re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', text)

def classify_finding(finding: str) -> str:
    f = finding.lower()
    if any(x in f for x in ["vulnerable", "confirmado", "activo", "ssrf", "system.multicall", "id_rsa", "phpinfo", "wp-config", "cve-"]):
        return "CRITICAL"
    if any(x in f for x in ["alerta", "posible", "enumeración", "expuesto", "listing", "backup"]):
        return "WARNING"
    return "INFO"

def display_finding(res):
    severity = classify_finding(res.get("Findings", ""))
    css_class = f"finding-{severity.lower()}"
    icon = "🔴" if severity == "CRITICAL" else "🟠" if severity == "WARNING" else "🔵"
    
    st.markdown(
        f'<div class="{css_class}">'
        f'<strong>{icon} {res["Endpoint"]}</strong><br/>'
        f'<span style="color:#cccccc; font-size:14px;">{res["Findings"]}</span>'
        f'</div>',
        unsafe_allow_html=True
    )

def render_technology_section(technologies):
    if not technologies:
        st.warning("No se detectaron tecnologías de forma confiable. Revisa que la fase de Reconocimiento Base no haya sido omitida.")
        return

    category_counts = {}
    for tech in technologies:
        category = tech.get("category", "Otra")
        category_counts[category] = category_counts.get(category, 0) + 1

    strongest = max(technologies, key=lambda item: item.get("confidence", 0))
    summary_html = (
        f'<div class="tech-summary">'
        f'<div class="tech-summary-item"><div class="tech-summary-label">Tecnologías</div><div class="tech-summary-value">{len(technologies)}</div></div>'
        f'<div class="tech-summary-item"><div class="tech-summary-label">Categorías</div><div class="tech-summary-value">{len(category_counts)}</div></div>'
        f'<div class="tech-summary-item"><div class="tech-summary-label">Mayor certeza</div><div class="tech-summary-value">{html_lib.escape(str(strongest.get("confidence", 0)))}%</div></div>'
        f'</div>'
    )
    st.markdown(summary_html, unsafe_allow_html=True)

    cards = []
    for tech in technologies:
        name = html_lib.escape(str(tech.get("name", "Desconocida")))
        category = html_lib.escape(str(tech.get("category", "Otra")))
        version = html_lib.escape(str(tech.get("version", "")))
        evidence = html_lib.escape(str(tech.get("evidence", "Evidencia no disponible")))
        confidence = int(tech.get("confidence", 0) or 0)
        icon = str(tech.get("icon", "") or "").strip()
        color = re.sub(r"[^0-9A-Fa-f]", "", str(tech.get("color", "64748b")))[:6] or "64748b"

        if icon:
            icon_html = f'<img class="tech-icon" alt="{name}" src="https://cdn.simpleicons.org/{html_lib.escape(icon)}/{color}" />'
        else:
            icon_html = f'<div class="tech-initial" style="border:2px solid #{color};">{name[:1].upper()}</div>'

        version_html = f'<span class="tech-version">v{version}</span>' if version else ""
        card_html = (
            f'<div class="tech-card">'
            f'<div class="tech-card-head">'
            f'{icon_html}'
            f'<div>'
            f'<div class="tech-name">{name}</div>'
            f'<div class="tech-category">{category}</div>'
            f'{version_html}'
            f'</div>'
            f'</div>'
            f'<div class="tech-evidence">{evidence}</div>'
            f'<div class="tech-confidence"><div class="tech-confidence-fill" style="width:{confidence}%; background:#{color};"></div></div>'
            f'<div class="tech-confidence-label">Certeza: {confidence}%</div>'
            f'</div>'
        )
        cards.append(card_html)

    st.markdown('<div class="tech-grid">' + "".join(cards) + "</div>", unsafe_allow_html=True)

def safe_pdf_text(value):
    return str(value or "").encode('latin-1', 'replace').decode('latin-1')

def add_technologies_to_pdf(pdf, technologies):
    pdf.set_font("helvetica", 'B', 10)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, safe_pdf_text("Tecnologías Detectadas"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    if not technologies:
        pdf.set_font("helvetica", '', 8)
        pdf.cell(0, 7, safe_pdf_text("No se detectaron tecnologías de forma confiable."), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)
        return

    category_counts = {}
    for tech in technologies:
        category = tech.get("category", "Otra")
        category_counts[category] = category_counts.get(category, 0) + 1

    strongest = max(technologies, key=lambda item: item.get("confidence", 0))
    pdf.set_font("helvetica", '', 8)
    summary = (
        f"Total: {len(technologies)} | Categorías: {len(category_counts)} | "
        f"Mayor certeza: {strongest.get('confidence', 0)}%"
    )
    pdf.cell(0, 7, safe_pdf_text(summary), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    tech_cols = ["Categoría", "Tecnología", "Versión", "Certeza", "Evidencia"]
    tech_widths = [30, 35, 23, 18, 84]
    with pdf.table(col_widths=tech_widths, line_height=5, text_align="LEFT") as table:
        header_row = table.row()
        pdf.set_font("helvetica", 'B', 7)
        for col in tech_cols:
            header_row.cell(safe_pdf_text(col))

        for tech in technologies:
            row = table.row()
            pdf.set_font("helvetica", '', 7)
            values = [
                tech.get("category", ""),
                tech.get("name", ""),
                tech.get("version", "") or "-",
                f"{tech.get('confidence', 0)}%",
                tech.get("evidence", ""),
            ]
            for value in values:
                row.cell(safe_pdf_text(value))

    pdf.ln(5)

# Initialize Session State
if "scan_completed" not in st.session_state:
    st.session_state.scan_completed = False
    st.session_state.results = []
    st.session_state.recon_cols_data = {}
    st.session_state.recon_plugins = ""
    st.session_state.recon_themes = ""
    st.session_state.technologies = []
    st.session_state.cve_warnings = []
    st.session_state.nvd_warning = ""
    st.session_state.phase_outputs = {}

# Tabs Layout
tab1, tab2, tab3 = st.tabs(["🔍 Auditoría", "📊 Dashboard", "📋 Detalle de Hallazgos"])

with tab1:
    st.header("🔍 Auditoría en Curso")
    run_clicked = st.button("🚀 Iniciar Auditoría", type="primary", width='stretch')
    
    if run_clicked:
        if not target_url.startswith("http"):
            st.error("Por favor, ingresa una URL válida (debe empezar con http:// o https://)")
        else:
            # Reset session state
            st.session_state.scan_completed = False
            st.session_state.results = []
            st.session_state.recon_cols_data = {}
            st.session_state.recon_plugins = ""
            st.session_state.recon_themes = ""
            st.session_state.technologies = []
            st.session_state.cve_warnings = []
            st.session_state.nvd_warning = ""
            st.session_state.phase_outputs = {}
            
            wordlist_param = wordlist if wordlist else None
            output_param = output_csv if output_csv else None

            # Progress logs container and status box
            with st.status("Ejecutando auditoría...", expanded=True) as status_box:
                
                def update_status_msg(msg):
                    clean_msg = strip_ansi(msg)
                    if clean_msg.strip():
                        status_box.write(clean_msg)
                
                auditor = WPAuditor(
                    target_url, 
                    wordlist_param, 
                    output_param, 
                    threads, 
                    delay, 
                    jitter,
                    nvd_key=nvd_key if nvd_key else None,
                    verify_ssl=verify_ssl,
                    on_progress=update_status_msg,
                    req_timeout=req_timeout
                )
                
                # Disable threading if delay/jitter is explicitly used
                if delay > 0 and threads > 1:
                    st.toast("Delay activado: Reduciendo hilos a 1 para evitar patrones agresivos de tráfico.", icon="⚠️")
                    auditor.threads = 1
                
                methods = [
                    ("recon", "Reconocimiento Base", auditor.recon),
                    ("active_plugins", "Escaneo Activo de Plugins", auditor.test_active_plugins),
                    ("headers", "Cabeceras de Seguridad", auditor.test_security_headers),
                    ("theme", "Detección de Temas", auditor.test_theme_version),
                    ("ports", "Escaneo de Puertos", auditor.test_ports),
                    ("ssl_tls", "Auditoría SSL/TLS", auditor.test_ssl_tls),
                    ("xmlrpc", "XML-RPC", auditor.test_xmlrpc),
                    ("rest", "REST API (Usuarios)", auditor.test_rest_users),
                    ("author", "Enum. Autores", auditor.test_author_enum),
                    ("login", "Enum. Login", auditor.test_login_enum),
                    ("cron", "DoS WP-Cron", auditor.test_wp_cron),
                    ("cli", "WP-CLI", auditor.test_wp_cli),
                    ("dir", "Directory Listing", auditor.check_directory_listing),
                    ("server_config", "Configuraciones del Servidor", auditor.test_server_config),
                    ("uploads", "Fugas en Uploads", auditor.test_uploads_leak),
                    ("classic", "Archivos Clásicos", auditor.test_classic_files),
                    ("passive_malware", "Análisis Pasivo de Malware", auditor.test_passive_malware),
                    ("routes", "Rutas Sensibles", auditor.scan_routes),
                ]
                
                # Fases exclusivas de WordPress que se omitirán si el sitio no es WP
                WP_ONLY_PHASES = {
                    "active_plugins", "theme", "xmlrpc", "rest", "author", "login", "cron",
                    "cli", "dir", "uploads", "routes"
                }

                methods_to_run = [m for m in methods if m[0] not in skip_phases]
                total_steps = len(methods_to_run)
                
                import asyncio
                import httpx

                async def run_scanner_async():
                    async with httpx.AsyncClient(verify=verify_ssl, timeout=req_timeout) as client:
                        auditor.client = client
                        abort_non_wp = False
                        for idx, (m_id, m_name, m_func) in enumerate(methods_to_run):
                            # Saltar fases WP-específicas si no se detectó WordPress
                            if abort_non_wp and m_id in WP_ONLY_PHASES:
                                status_box.write(f"⏭️ Fase omitida (sitio no es WordPress): **{m_name}**")
                                st.session_state.phase_outputs[m_id] = {
                                    "name": m_name,
                                    "output": "Fase omitida: WordPress no detectado en el objetivo.",
                                    "results": []
                                }
                                continue
                            
                            status_box.update(label=f"Ejecutando: {m_name}...", state="running")
                            
                            # Capture stdout for compatibility and parsing
                            old_stdout = sys.stdout
                            buffer = io.StringIO()
                            sys.stdout = buffer
                            
                            start_len = len(auditor.results)
                            try:
                                await m_func()
                            except Exception as e:
                                print(f"Error en fase {m_name}: {e}")
                                
                            sys.stdout = old_stdout
                            output = strip_ansi(buffer.getvalue())
                            phase_results = auditor.results[start_len:]
                            
                            # Save results to session state for rendering
                            st.session_state.phase_outputs[m_id] = {
                                "name": m_name,
                                "output": output,
                                "results": phase_results
                            }
                            
                            if m_id == "recon":
                                server = re.search(r'Servidor\s*:\s*(.*)', output)
                                php = re.search(r'Versión PHP\s*:\s*(.*)', output)
                                wp = re.search(r'Versión WP\s*:\s*(.*)', output)
                                waf = re.search(r'WAF / Proxy\s*:\s*(.*)', output)
                                themes = re.search(r'Temas Activos\s*:\s*(.*)', output)
                                
                                st.session_state.recon_cols_data = {
                                    "Server": server.group(1).strip() if server else '-',
                                    "WordPress": wp.group(1).strip() if wp else '-',
                                    "PHP": php.group(1).strip() if php else '-',
                                    "WAF": waf.group(1).strip() if waf else '-'
                                }
                                
                                plugins_match = re.search(r'Plugins\s*:\s*(.*)', output)
                                st.session_state.recon_plugins = plugins_match.group(1).strip() if plugins_match else '-'
                                st.session_state.recon_themes = themes.group(1).strip() if themes else '-'
                                st.session_state.technologies = getattr(auditor, "detected_technologies", [])

                                # ── Verificación crítica: ¿Es WordPress? ──
                                if not auditor.is_wordpress:
                                    abort_non_wp = True
                                    status_box.write(
                                        "⚠️ **WordPress NO detectado** en el objetivo. "
                                        "Se omitirán todas las fases exclusivas de WordPress para ahorrar tiempo."
                                    )

                try:
                    asyncio.run(run_scanner_async())
                except Exception as run_err:
                    st.error(f"Error durante la ejecución del escáner: {run_err}")
                
                status_box.update(label="¡Auditoría Completada!", state="complete", expanded=False)
            
            st.session_state.results = auditor.results
            st.session_state.scan_completed = True
            
            # Extract CVEs from structured results to ensure 100% accuracy
            st.session_state.cve_warnings = [
                res["Findings"] for res in st.session_state.results if res.get("Module") == "CVE-Scanner"
            ]
            
            # Check if any phase encountered a rate limit or API error
            has_rate_limit = any(
                "Rate limit" in data.get("output", "") or "Error consultando" in data.get("output", "")
                for data in st.session_state.phase_outputs.values()
            )
            
            if has_rate_limit:
                st.session_state.nvd_warning = "RateLimit"
            elif st.session_state.cve_warnings:
                st.session_state.nvd_warning = "Vulnerable"
            else:
                st.session_state.nvd_warning = "Clean"
            
            # Export CSV on server
            auditor.export_results()

    # Always render completion UI in Tab 1 if completed
    if st.session_state.scan_completed:
        st.subheader("📋 Resultados del Escaneo")
        
        # Display Recon
        if st.session_state.recon_cols_data:
            recon_cols = st.columns(4)
            recon_cols[0].markdown(f"<div class='metric-card'><div class='metric-card-title'>Servidor</div><div class='metric-card-value'>{st.session_state.recon_cols_data.get('Server', '-')}</div></div>", unsafe_allow_html=True)
            recon_cols[1].markdown(f"<div class='metric-card'><div class='metric-card-title'>Versión WP</div><div class='metric-card-value'>{st.session_state.recon_cols_data.get('WordPress', '-')}</div></div>", unsafe_allow_html=True)
            recon_cols[2].markdown(f"<div class='metric-card'><div class='metric-card-title'>PHP</div><div class='metric-card-value'>{st.session_state.recon_cols_data.get('PHP', '-')}</div></div>", unsafe_allow_html=True)
            recon_cols[3].markdown(f"<div class='metric-card'><div class='metric-card-title'>WAF / Proxy</div><div class='metric-card-value'>{st.session_state.recon_cols_data.get('WAF', '-')}</div></div>", unsafe_allow_html=True)
            
            st.info(f"🧩 **Plugins Detectados:** {st.session_state.recon_plugins}")
            st.info(f"🎨 **Temas Activos:** {st.session_state.recon_themes}")
            
            st.subheader("Tecnologías detectadas")
            render_technology_section(st.session_state.technologies)

            if st.session_state.cve_warnings:
                st.error("🚨 **Vulnerabilidades CVE Detectadas (NVD):**\n\n" + "\n".join([f"- **{m.strip()}**" for m in st.session_state.cve_warnings]))
            elif st.session_state.nvd_warning == "RateLimit":
                st.warning("⚠️ **Validación NVD:** No se pudo consultar la base de datos (límite de peticiones de la API).")
            elif st.session_state.nvd_warning == "Clean":
                st.success("✅ **Validación NVD:** No se encontraron CVEs críticos publicados para las versiones detectadas.")
        
        # Display each phase result expander
        for m_id, phase_data in st.session_state.phase_outputs.items():
            if m_id == "recon":
                continue
            m_name = phase_data["name"]
            phase_results = phase_data["results"]
            
            with st.expander(f"📦 Fase: {m_name}", expanded=bool(phase_results)):
                if not phase_results:
                    st.success("✅ No se detectaron vulnerabilidades o exposiciones en esta fase.")
                else:
                    for res in phase_results:
                        display_finding(res)

with tab2:
    st.header("📊 Dashboard Final de Resultados")
    if st.session_state.scan_completed and st.session_state.results:
        df = pd.DataFrame(st.session_state.results)
        df['Severity'] = df['Findings'].apply(classify_finding)
        
        kpi1, kpi2, kpi3 = st.columns(3)
        kpi1.metric("🔴 Críticos", len(df[df['Severity'] == 'CRITICAL']))
        kpi2.metric("🟠 Advertencias", len(df[df['Severity'] == 'WARNING']))
        kpi3.metric("🔵 Informativos", len(df[df['Severity'] == 'INFO']))
        
        c1, c2 = st.columns(2)
        color_map = {'CRITICAL': '#ff0055', 'WARNING': '#ffcc00', 'INFO': '#00f3ff'}
        
        with c1:
            fig_pie = px.pie(df, names='Severity', title='Severidad Global', color='Severity', color_discrete_map=color_map, hole=0.4)
            fig_pie.update_traces(textposition='inside', textinfo='percent+label')
            fig_pie.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', font_color='#ccd6f6')
            st.plotly_chart(fig_pie, width='stretch')
            
        with c2:
            mod_counts = df.groupby(['Module', 'Severity']).size().reset_index(name='Count')
            fig_bar = px.bar(mod_counts, x='Module', y='Count', color='Severity', title='Hallazgos por Módulo', color_discrete_map=color_map, text_auto=True)
            fig_bar.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', font_color='#ccd6f6')
            st.plotly_chart(fig_bar, width='stretch')
    else:
        st.info("Por favor, inicia la auditoría en la pestaña 'Auditoría' para ver estadísticas.")

with tab3:
    st.header("📋 Datos Detallados de la Auditoría")
    if st.session_state.scan_completed and st.session_state.results:
        df = pd.DataFrame(st.session_state.results)
        df['Severity'] = df['Findings'].apply(classify_finding)
        
        # Table styles
        def color_severity(val):
            if val == "CRITICAL": return "background-color: rgba(255, 0, 85, 0.2); color: #ff0055;"
            elif val == "WARNING": return "background-color: rgba(255, 204, 0, 0.2); color: #ffcc00;"
            elif val == "INFO": return "background-color: rgba(0, 243, 255, 0.2); color: #00f3ff;"
            return ""
        
        df["Status"] = df["Status"].astype(str)
        df["Findings"] = df["Findings"].astype(str)
        styled_df = df[["Severity", "Module", "Endpoint", "Status", "Findings"]].style.map(color_severity, subset=['Severity'])
        st.dataframe(styled_df, width='stretch')
        
        # Download options
        csv = df.to_csv(index=False).encode('utf-8')
        technologies_df = pd.DataFrame(st.session_state.technologies)
        technologies_csv = technologies_df.to_csv(index=False).encode('utf-8') if not technologies_df.empty else b""
        
        c_btn1, c_btn2, c_btn3 = st.columns(3)
        with c_btn1:
            st.download_button("📥 Descargar CSV", data=csv, file_name=output_csv if output_csv else 'resultados.csv', mime='text/csv', width='stretch')
            
        with c_btn2:
            st.download_button("Tecnologías CSV", data=technologies_csv, file_name="tecnologias_detectadas.csv", mime='text/csv', width='stretch', disabled=technologies_df.empty)

        with c_btn3:
            with st.spinner("Generando PDF... (puede tomar unos segundos)"):
                try:
                    pdf = FPDF(orientation="P", unit="mm", format="A4")
                    pdf.add_page()
                    pdf.set_auto_page_break(auto=True, margin=15)
                    
                    # Target Name parsing
                    from urllib.parse import urlparse
                    parsed_url = urlparse(target_url)
                    clean_target_name = parsed_url.netloc or target_url
                    
                    target_domain = clean_target_name.replace(":", "_").replace(".", "_")
                    target_domain = re.sub(r'[^a-zA-Z0-9_]', '', target_domain)
                    pdf_filename = f"reporte_auditoria_{target_domain}.pdf"
                    
                    # Title
                    pdf.set_font("helvetica", 'B', 16)
                    pdf.cell(0, 10, safe_pdf_text(f"Auditoria de Seguridad WordPress - {clean_target_name}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
                    pdf.set_font("helvetica", 'I', 11)
                    pdf.cell(0, 8, f"Objetivo: {target_url}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
                    
                    import datetime
                    fecha_escaneo = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    pdf.set_font("helvetica", 'I', 9)
                    pdf.cell(0, 6, safe_pdf_text(f"Fecha del Escaneo: {fecha_escaneo}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
                    pdf.ln(5)
                    
                    # Platform Info Table
                    pdf.set_font("helvetica", 'B', 11)
                    pdf.cell(0, 8, safe_pdf_text("Resumen del Servidor y Reconocimiento"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.ln(1)
                    
                    recon_info = [
                        ["Servidor Web", st.session_state.recon_cols_data.get("Server", "-")],
                        ["Version WordPress", st.session_state.recon_cols_data.get("WordPress", "-")],
                        ["Version PHP", st.session_state.recon_cols_data.get("PHP", "-")],
                        ["WAF / Proxy", st.session_state.recon_cols_data.get("WAF", "-")],
                        ["Temas Activos", st.session_state.recon_themes or "-"],
                        ["Plugins Detectados", st.session_state.recon_plugins or "-"]
                    ]
                    
                    with pdf.table(col_widths=[45, 145], line_height=5, text_align="LEFT") as table:
                        for row in recon_info:
                            data_row = table.row()
                            pdf.set_font("helvetica", 'B', 8)
                            data_row.cell(safe_pdf_text(row[0]))
                            pdf.set_font("helvetica", '', 8)
                            data_row.cell(safe_pdf_text(row[1]))
                    
                    pdf.ln(5)
                    
                    # KPIs
                    pdf.set_font("helvetica", 'B', 12)
                    pdf.set_text_color(0, 0, 0)
                    kpi_crit = len(df[df['Severity'] == 'CRITICAL'])
                    kpi_warn = len(df[df['Severity'] == 'WARNING'])
                    kpi_info = len(df[df['Severity'] == 'INFO'])
                    pdf.cell(0, 10, f"Resumen: {kpi_crit} Criticos | {kpi_warn} Advertencias | {kpi_info} Informativos", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.ln(5)
                    
                    # PDF Charts
                    pdf_color_map = {'CRITICAL': '#cc0044', 'WARNING': '#ccaa00', 'INFO': '#0088aa'}
                    fig_pie_pdf = px.pie(df, names='Severity', title='Severidad Global', color='Severity', color_discrete_map=pdf_color_map, hole=0.4)
                    fig_pie_pdf.update_traces(textposition='inside', textinfo='percent+label')
                    fig_pie_pdf.update_layout(font_color='black', paper_bgcolor='white', plot_bgcolor='white')
                    
                    mod_counts = df.groupby(['Module', 'Severity']).size().reset_index(name='Count')
                    fig_bar_pdf = px.bar(mod_counts, x='Module', y='Count', color='Severity', title='Hallazgos por Módulo', color_discrete_map=pdf_color_map, text_auto=True)
                    fig_bar_pdf.update_layout(font_color='black', paper_bgcolor='white', plot_bgcolor='white')
                    
                    pie_path = None
                    bar_path = None
                    try:
                        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp_pie:
                            fig_pie_pdf.write_image(tmp_pie.name, width=400, height=300)
                            pie_path = tmp_pie.name
                        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp_bar:
                            fig_bar_pdf.write_image(tmp_bar.name, width=400, height=300)
                            bar_path = tmp_bar.name
                    except Exception as img_err:
                        pass # Silently skip charts if kaleido is missing
                        
                    if pie_path and bar_path:
                        pdf.image(pie_path, x=10, y=pdf.get_y(), w=90)
                        pdf.image(bar_path, x=105, y=pdf.get_y(), w=90)
                        pdf.ln(75)

                    add_technologies_to_pdf(pdf, st.session_state.technologies)
                    
                    # Table details
                    pdf.set_font("helvetica", 'B', 10)
                    pdf.set_text_color(0, 0, 0)
                    pdf.cell(0, 10, "Detalle de Hallazgos", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.ln(2)
                    
                    # Columns and table construction with fpdf2
                    col_widths = [18, 22, 45, 15, 90]
                    cols = ["Severity", "Module", "Endpoint", "Status", "Findings"]
                    
                    with pdf.table(col_widths=col_widths, line_height=5, text_align="LEFT") as table:
                        # Headers
                        headers_row = table.row()
                        pdf.set_font("helvetica", 'B', 8)
                        pdf.set_text_color(0, 0, 0)
                        for col in cols:
                            headers_row.cell(col)
                        
                        # Rows
                        for index, row in df.iterrows():
                            data_row = table.row()
                            severity = str(row["Severity"])
                            for col in cols:
                                val = str(row[col])
                                val = val.encode('latin-1', 'replace').decode('latin-1')
                                
                                # Color code severity column
                                if col == "Severity":
                                    if severity == "CRITICAL":
                                        pdf.set_text_color(204, 0, 68)  # Rich Critical Pink-Red
                                        pdf.set_font("helvetica", 'B', 7)
                                    elif severity == "WARNING":
                                        pdf.set_text_color(204, 110, 0)  # Rich Warning Orange-Yellow
                                        pdf.set_font("helvetica", 'B', 7)
                                    else:
                                        pdf.set_text_color(0, 100, 180)  # Rich Info Blue
                                        pdf.set_font("helvetica", 'B', 7)
                                else:
                                    pdf.set_text_color(0, 0, 0)
                                    pdf.set_font("helvetica", '', 7)
                                
                                data_row.cell(val)
                                
                    pdf_out = pdf.output()
                    if isinstance(pdf_out, str):
                        pdf_bytes = pdf_out.encode('latin-1')
                    else:
                        pdf_bytes = bytes(pdf_out)
                        
                    st.download_button("📄 Descargar PDF", data=pdf_bytes, file_name=pdf_filename, mime="application/pdf", width='stretch')
                    
                except Exception as e:
                    st.error(f"Error generando el PDF: {e}")
    else:
        st.info("Por favor, inicia la auditoría en la pestaña 'Auditoría' para descargar resultados.")
