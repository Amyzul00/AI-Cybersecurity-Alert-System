from pathlib import Path
code = r'''"""
Warisan Security Malware Operations - Streamlit Application

Database:
    MySQL database configured in database.py (cybersecurity_db)

Email:
    Configure Streamlit secrets in .streamlit/secrets.toml or Streamlit Cloud:
        [email]
        sender = "your-email@gmail.com"
        app_password = "your-google-app-password"

Never commit secrets.toml or real credentials to Git.
"""

import base64
import hashlib
import hmac
import html
import os
import random
import secrets
import smtplib
import time
from datetime import datetime
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from io import BytesIO

import pandas as pd
import plotly.express as px
import streamlit as st
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    Image as RLImage,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from database import (
    get_db_connection,
    init_db,
    fetch_recent_threats,
    log_threat,
)

try:
    from log_integration import handle_security_event
except ImportError:
    def handle_security_event(message, is_critical=False):
        print(f"[SOAR EVENT] critical={is_critical}: {message}")


# ---------------------------------------------------------------------
# PAGE CONFIGURATION
# ---------------------------------------------------------------------
st.set_page_config(
    page_title="Warisan Security Malware Operations - AI Threat Detection",
    page_icon="🛡️",
    layout="wide",
)

LOGO_PATH = "Logo.png"
OTP_LIFETIME_SECONDS = 300
PASSWORD_ITERATIONS = 310_000


# ---------------------------------------------------------------------
# DATABASE INITIALIZATION AND USER HELPERS (MYSQL)
# ---------------------------------------------------------------------
@st.cache_resource
def initialize_database():
    """Initialize the MySQL tables using database.py."""
    init_db()
    return True


try:
    initialize_database()
except Exception as exc:
    st.error(
        "Unable to connect to the MySQL database. Check database.py, "
        "MySQL service, database name, username and password."
    )
    st.exception(exc)
    st.stop()


def get_user_by_login(login_value):
    """Find a user by username or email in MySQL."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT id, username, email, role, password
            FROM users
            WHERE username = %s OR email = %s
            LIMIT 1
            """,
            (login_value.strip(), login_value.strip().lower()),
        )
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()


def get_user_by_username(username):
    """Retrieve one user by username."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT id, username, email, role, password
            FROM users
            WHERE username = %s
            LIMIT 1
            """,
            (username,),
        )
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()


def hash_password(password):
    """Hash a password using PBKDF2-HMAC-SHA256."""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PASSWORD_ITERATIONS,
    ).hex()
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt}${digest}"


def verify_password(plain_password, stored_password):
    """
    Verify a PBKDF2 password hash.
    Legacy plaintext passwords are temporarily supported for migration.
    """
    if not stored_password:
        return False, False

    if stored_password.startswith("pbkdf2_sha256$"):
        try:
            algorithm, iterations, salt, expected = stored_password.split("$", 3)
            if algorithm != "pbkdf2_sha256":
                return False, False
            actual = hashlib.pbkdf2_hmac(
                "sha256",
                plain_password.encode("utf-8"),
                salt.encode("utf-8"),
                int(iterations),
            ).hex()
            return hmac.compare_digest(actual, expected), False
        except (ValueError, TypeError):
            return False, False

    # Existing database.py registrations stored plaintext passwords.
    # Accept once, then upgrade the value to a PBKDF2 hash at login.
    if hmac.compare_digest(plain_password, str(stored_password)):
        return True, True

    return False, False


def upgrade_legacy_password(user_id, plain_password):
    """Upgrade a legacy plaintext password after a successful login."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE users SET password = %s WHERE id = %s",
            (hash_password(plain_password), user_id),
        )
        conn.commit()
    finally:
        cursor.close()
        conn.close()


def create_user(username, email, password):
    """Create a user in MySQL with a securely hashed password."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO users (username, email, role, password)
            VALUES (%s, %s, %s, %s)
            """,
            (
                username.strip(),
                email.strip().lower(),
                "user",
                hash_password(password),
            ),
        )
        conn.commit()
        return True, None
    except Exception as exc:
        conn.rollback()
        # MySQL duplicate-key error is commonly error code 1062.
        if getattr(exc, "args", [None])[0] == 1062:
            return False, "Username or email already exists."
        return False, str(exc)
    finally:
        cursor.close()
        conn.close()


def get_registered_user_emails():
    """Read registered recipient email addresses from MySQL."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT email
            FROM users
            WHERE email IS NOT NULL AND email <> ''
            """
        )
        rows = cursor.fetchall()
        return [
            row["email"].strip()
            for row in rows
            if row.get("email") and "@" in row["email"]
        ]
    finally:
        cursor.close()
        conn.close()


# ---------------------------------------------------------------------
# EMAIL CONFIGURATION AND SMTP HELPERS
# ---------------------------------------------------------------------
def get_smtp_settings():
    """
    Read Gmail credentials from Streamlit Secrets.
    Environment variables are supported for local/server deployments.
    """
    sender = None
    app_password = None

    try:
        sender = st.secrets["email"]["sender"]
        app_password = st.secrets["email"]["app_password"]
    except Exception:
        sender = os.getenv("SMTP_SENDER")
        app_password = os.getenv("SMTP_APP_PASSWORD")

    if not sender or not app_password:
        raise ValueError(
            "Email credentials are missing. Configure [email] sender and "
            "app_password in .streamlit/secrets.toml or Streamlit Cloud Secrets."
        )

    return str(sender).strip(), str(app_password).replace(" ", "").strip()


def send_email_notification(receiver_email, subject, content, is_html=True):
    """Send one email using Gmail SMTP with TLS."""
    server = None
    try:
        sender_email, app_password = get_smtp_settings()

        message = MIMEMultipart()
        message["Subject"] = subject
        message["From"] = sender_email
        message["To"] = receiver_email
        message.attach(
            MIMEText(content, "html" if is_html else "plain", "utf-8")
        )

        server = smtplib.SMTP("smtp.gmail.com", 587, timeout=25)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(sender_email, app_password)
        server.sendmail(sender_email, [receiver_email], message.as_string())
        return True, None

    except Exception as exc:
        print(f"[EMAIL ERROR] {exc}")
        return False, str(exc)

    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass


def send_email_with_attachment(
    receiver_email, subject, body, attachment_bytes,
    attachment_name="executive_threat_report.pdf"
):
    """Send an email with an in-memory PDF attachment."""
    server = None
    try:
        sender_email, app_password = get_smtp_settings()

        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = receiver_email
        message["Subject"] = subject
        message.attach(MIMEText(body, "plain", "utf-8"))

        attachment = MIMEApplication(attachment_bytes, Name=attachment_name)
        attachment.add_header(
            "Content-Disposition",
            "attachment",
            filename=attachment_name,
        )
        message.attach(attachment)

        server = smtplib.SMTP("smtp.gmail.com", 587, timeout=25)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(sender_email, app_password)
        server.sendmail(sender_email, [receiver_email], message.as_string())
        return True, None

    except Exception as exc:
        print(f"[EMAIL ATTACHMENT ERROR] {exc}")
        return False, str(exc)

    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass


def auto_send_lstm_threat_alert(threat_label, confidence_score=None):
    """Broadcast a threat alert to email addresses stored in MySQL."""
    try:
        recipients = get_registered_user_emails()
    except Exception as exc:
        print(f"[DATABASE EMAIL LOOKUP ERROR] {exc}")
        return 0

    if not recipients:
        return 0

    confidence_text = (
        f"{float(confidence_score):.2f}%"
        if confidence_score is not None
        else "Not available"
    )

    subject = f"SECURITY ALERT: {threat_label} Detected"
    body = f"""
    WARISAN SECURITY - THREAT ALERT

    A potential security threat has been detected.

    Threat classification: {threat_label}
    Model confidence: {confidence_text}

    Please sign in to the Warisan Security dashboard to review the event.

    This is an automated notification.
    """

    sent_count = 0
    for recipient in recipients:
        success, error = send_email_notification(
            recipient, subject, body, is_html=False
        )
        if success:
            sent_count += 1
        else:
            print(f"[EMAIL FAILED] {recipient}: {error}")

    return sent_count


# ---------------------------------------------------------------------
# LOGO AND SESSION STATE
# ---------------------------------------------------------------------
def get_base64_image(image_path):
    try:
        with open(image_path, "rb") as image_file:
            encoded = base64.b64encode(image_file.read()).decode("utf-8")
            return f"data:image/png;base64,{encoded}"
    except (OSError, ValueError):
        return ""


logo_base64 = get_base64_image(LOGO_PATH)


def initialize_session_state():
    defaults = {
        "logged_in": False,
        "username": "",
        "role": "",
        "email": "",
        "otp_required": False,
        "generated_otp": "",
        "otp_expires_at": 0.0,
        "temp_username": "",
        "temp_role": "",
        "temp_email": "",
        "last_alerted_threat": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


initialize_session_state()


def clear_otp_state():
    st.session_state["otp_required"] = False
    st.session_state["generated_otp"] = ""
    st.session_state["otp_expires_at"] = 0.0
    st.session_state["temp_username"] = ""
    st.session_state["temp_role"] = ""
    st.session_state["temp_email"] = ""


# ---------------------------------------------------------------------
# PDF REPORT
# ---------------------------------------------------------------------
def generate_pdf_report(dataframe):
    """Generate the dashboard PDF report in memory."""
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=30,
        leftMargin=30,
        topMargin=30,
        bottomMargin=30,
    )

    elements = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=16,
        textColor=colors.HexColor("#ff4b4b"),
        spaceAfter=3,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=8,
        textColor=colors.HexColor("#6c757d"),
        spaceAfter=10,
    )

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    heading = [
        Paragraph("Warisan Security Malware Operations Report", title_style),
        Paragraph(f"Generated: {timestamp}", subtitle_style),
    ]

    try:
        if os.path.exists(LOGO_PATH):
            pil_image = RLImage(LOGO_PATH, width=42, height=42)
            header = Table([[pil_image, heading]], colWidths=[55, 480])
            header.setStyle(
                TableStyle([
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                ])
            )
            elements.append(header)
        else:
            elements.extend(heading)
    except Exception:
        elements.extend(heading)

    elements.append(Spacer(1, 15))

    total = len(dataframe)
    critical = (
        int((dataframe["Status"] == "CRITICAL").sum())
        if "Status" in dataframe.columns else 0
    )
    warning = (
        int((dataframe["Status"] == "WARNING").sum())
        if "Status" in dataframe.columns else 0
    )
    average_confidence = (
        float(dataframe["Confidence"].mean())
        if not dataframe.empty and "Confidence" in dataframe.columns
        else 0.0
    )

    summary = [
        ["Metric", "Value"],
        ["Total displayed events", str(total)],
        ["Critical events", str(critical)],
        ["Warning events", str(warning)],
        ["Average confidence", f"{average_confidence:.1f}%"],
    ]
    summary_table = Table(summary, colWidths=[220, 150])
    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e222d")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f1f3f5")),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#212529")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 7),
        ])
    )
    elements.append(summary_table)
    elements.append(Spacer(1, 16))
    elements.append(Paragraph("Detailed Threat Event Log", styles["Heading2"]))

    columns = ["IP", "Status", "Threat", "Confidence"]
    report_df = dataframe.copy()
    for column in columns:
        if column not in report_df.columns:
            report_df[column] = ""

    table_data = [["IP Address", "Status", "Threat", "Confidence"]]
    for row in report_df[columns].itertuples(index=False, name=None):
        table_data.append([
            str(row[0]),
            str(row[1]),
            str(row[2]),
            f"{float(row[3]):.1f}%" if row[3] != "" else "",
        ])

    detail_table = Table(
        table_data,
        colWidths=[125, 95, 145, 95],
        repeatRows=1,
    )
    detail_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e222d")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8f9fa")),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#212529")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 6),
        ])
    )
    elements.append(detail_table)

    document.build(elements)
    buffer.seek(0)
    return buffer.getvalue()


# ---------------------------------------------------------------------
# LOGIN, OTP AND REGISTRATION
# ---------------------------------------------------------------------
def render_authentication():
    logo_html = (
        f'<img src="{logo_base64}" style="width:90px;height:90px;'
        'border-radius:50%;object-fit:cover;border:2px solid #ff4b4b;'
        'margin-bottom:12px;" alt="Logo">'
        if logo_base64
        else '<div style="font-size:3rem;">🛡️</div>'
    )

    st.markdown(
        f"""
        <div style="text-align:center;padding:20px;">
            {logo_html}
            <h1 style="color:#ff4b4b;margin:0;">
                Warisan Security Malware Operations
            </h1>
            <p style="color:#8a99ad;">
                Secure Login, Email OTP Verification and Account Registration
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    _, center, _ = st.columns([1, 2, 1])

    with center:
        if st.session_state["otp_required"]:
            st.info(
                "A verification code was sent to "
                f"**{st.session_state['temp_email']}**."
            )
            st.subheader("Email OTP Verification")

            with st.form("otp_verification_form"):
                entered_otp = st.text_input(
                    "Enter your 6-digit OTP",
                    type="password",
                    max_chars=6,
                )
                verify_clicked = st.form_submit_button(
                    "Verify & Login",
                    use_container_width=True,
                )

            cancel_col, _ = st.columns(2)
            with cancel_col:
                if st.button("Cancel", use_container_width=True):
                    clear_otp_state()
                    st.rerun()

            if verify_clicked:
                if time.time() > st.session_state["otp_expires_at"]:
                    clear_otp_state()
                    st.error("Your OTP has expired. Please log in again.")
                    st.rerun()

                elif secrets.compare_digest(
                    entered_otp,
                    st.session_state["generated_otp"],
                ):
                    st.session_state["logged_in"] = True
                    st.session_state["username"] = st.session_state["temp_username"]
                    st.session_state["role"] = st.session_state["temp_role"]
                    st.session_state["email"] = st.session_state["temp_email"]
                    clear_otp_state()
                    st.success("OTP verified. Welcome to the dashboard!")
                    st.rerun()
                else:
                    st.error("Incorrect OTP. Please try again.")

        else:
            login_tab, register_tab = st.tabs(["🔑 Login", "📝 Register"])

            with login_tab:
                st.subheader("System Login (Email 2FA)")

                with st.form("login_form"):
                    login_value = st.text_input("Username or Email")
                    password = st.text_input("Password", type="password")
                    login_clicked = st.form_submit_button(
                        "Proceed to OTP Verification",
                        use_container_width=True,
                    )

                if login_clicked:
                    if not login_value.strip() or not password:
                        st.warning("Please enter your username/email and password.")
                    else:
                        try:
                            user = get_user_by_login(login_value)
                            if not user:
                                st.error("Incorrect username/email or password.")
                            else:
                                valid, needs_upgrade = verify_password(
                                    password, user["password"]
                                )

                                if not valid:
                                    st.error("Incorrect username/email or password.")
                                elif not user.get("email"):
                                    st.error(
                                        "This account has no registered email address. "
                                        "Contact the administrator."
                                    )
                                else:
                                    if needs_upgrade:
                                        upgrade_legacy_password(user["id"], password)

                                    otp = f"{secrets.randbelow(900000) + 100000}"
                                    safe_username = html.escape(user["username"])
                                    safe_otp = html.escape(otp)

                                    otp_html = f"""
                                    <html>
                                    <body style="font-family:Arial,sans-serif;">
                                        <h2 style="color:#ff4b4b;">
                                            Warisan Security Verification
                                        </h2>
                                        <p>Hello {safe_username},</p>
                                        <p>Your login verification code is:</p>
                                        <h1 style="letter-spacing:8px;color:#ff4b4b;">
                                            {safe_otp}
                                        </h1>
                                        <p>This code expires in 5 minutes.</p>
                                        <p>If you did not request this code,
                                        please ignore this email.</p>
                                    </body>
                                    </html>
                                    """

                                    sent, email_error = send_email_notification(
                                        user["email"],
                                        "Warisan Security - Login OTP",
                                        otp_html,
                                        is_html=True,
                                    )

                                    if sent:
                                        st.session_state["generated_otp"] = otp
                                        st.session_state["otp_expires_at"] = (
                                            time.time() + OTP_LIFETIME_SECONDS
                                        )
                                        st.session_state["temp_username"] = user["username"]
                                        st.session_state["temp_role"] = str(
                                            user["role"] or "user"
                                        ).lower()
                                        st.session_state["temp_email"] = user["email"]
                                        st.session_state["otp_required"] = True
                                        st.success("OTP sent to your registered email.")
                                        st.rerun()
                                    else:
                                        st.error(
                                            "Unable to send OTP email. Check SMTP "
                                            "Secrets and Gmail settings."
                                        )
                                        st.caption(str(email_error))

                        except Exception as exc:
                            st.error(f"Login/database error: {exc}")

            with register_tab:
                st.subheader("Register New Account")

                with st.form("registration_form"):
                    reg_username = st.text_input("Choose Username")
                    reg_email = st.text_input("Email Address")
                    reg_password = st.text_input(
                        "Choose Password", type="password"
                    )
                    confirm_password = st.text_input(
                        "Confirm Password", type="password"
                    )
                    register_clicked = st.form_submit_button(
                        "Register Account",
                        use_container_width=True,
                    )

                if register_clicked:
                    if not all([
                        reg_username.strip(),
                        reg_email.strip(),
                        reg_password,
                        confirm_password,
                    ]):
                        st.warning("Please complete all registration fields.")
                    elif "@" not in reg_email or "." not in reg_email.split("@")[-1]:
                        st.warning("Please enter a valid email address.")
                    elif len(reg_password) < 8:
                        st.warning("Password must contain at least 8 characters.")
                    elif reg_password != confirm_password:
                        st.error("Passwords do not match.")
                    else:
                        try:
                            created, error = create_user(
                                reg_username, reg_email, reg_password
                            )
                            if created:
                                st.success(
                                    "Account registered successfully. "
                                    "You can now log in."
                                )
                            elif error == "Username or email already exists.":
                                st.error(error)
                            else:
                                st.error(f"Registration failed: {error}")
                        except Exception as exc:
                            st.error(f"Registration/database error: {exc}")


if not st.session_state["logged_in"]:
    render_authentication()
    st.stop()


# ---------------------------------------------------------------------
# DASHBOARD HEADER AND STYLING
# ---------------------------------------------------------------------
st.markdown(
    """
    <style>
    .main { background-color: #0e1117; }
    div[data-testid="stMetricValue"] {
        font-size: 1.8rem;
        font-weight: 700;
    }
    div[data-testid="stMetric"] {
        background-color: #1e222d;
        border-radius: 8px;
        padding: 15px;
        border-left: 4px solid #ff4b4b;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

header_col, button_col = st.columns([4, 1])

with header_col:
    if logo_base64:
        st.markdown(
            f"""
            <div style="display:flex;align-items:center;gap:20px;">
                <img src="{logo_base64}" style="width:90px;height:90px;
                border-radius:50%;object-fit:cover;border:2px solid #ff4b4b;">
                <div>
                    <h1 style="margin:0;color:white;">
                        Warisan Security Malware Operations
                    </h1>
                    <p style="color:#8a99ad;margin-top:5px;">
                        Dynamic Threat Detection, Automated Incident Analytics & SOAR
                    </p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.title("Warisan Security Malware Operations")
        st.caption("Dynamic Threat Detection, Analytics & SOAR")

with button_col:
    st.write("")
    if st.button("🔄 Refresh & Rescan", use_container_width=True):
        st.cache_data.clear()
        st.rerun()


# ---------------------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------------------
if logo_base64:
    st.sidebar.markdown(
        f'<div style="text-align:center;"><img src="{logo_base64}" '
        'style="width:85px;height:85px;border-radius:50%;'
        'object-fit:cover;border:2px solid #ff4b4b;"></div>',
        unsafe_allow_html=True,
    )

st.sidebar.markdown(
    f"**User:** {st.session_state['username']}  \n"
    f"**Role:** {st.session_state['role'].upper()}"
)

if st.sidebar.button("🚪 Logout", use_container_width=True):
    st.session_state["logged_in"] = False
    st.session_state["username"] = ""
    st.session_state["role"] = ""
    st.session_state["email"] = ""
    clear_otp_state()
    st.rerun()

st.sidebar.divider()
st.sidebar.subheader("🚨 Notification & Alert Center")

try:
    recent_threats = fetch_recent_threats(limit=10)
except Exception as exc:
    recent_threats = []
    st.sidebar.error(f"Unable to load MySQL threat logs: {exc}")

if recent_threats:
    for threat in recent_threats:
        severity = str(threat.get("severity", "")).lower()
        threat_id = threat.get("id")

        if severity in ("high", "critical") and threat_id is not None:
            alert_key = f"email_sent_threat_{threat_id}"
            if not st.session_state.get(alert_key, False):
                with st.sidebar.expander(
                    f"Threat #{threat_id}: {threat.get('threat_type', 'Unknown')}"
                ):
                    st.write(f"Source IP: {threat.get('src_ip', 'N/A')}")
                    st.write(f"Severity: {severity.upper()}")
                    if st.button(
                        "Send email alert",
                        key=f"send_alert_{threat_id}",
                    ):
                        count = auto_send_lstm_threat_alert(
                            threat.get("threat_type", "Unknown")
                        )
                        st.session_state[alert_key] = True
                        st.success(f"Sent to {count} registered user(s).")
else:
    st.sidebar.caption("No recent threat alerts logged yet.")


# ---------------------------------------------------------------------
# DETECTION ENGINE / PREDICTIONS
# ---------------------------------------------------------------------
@st.cache_data(ttl=15)
def get_backend_predictions():
    """
    Attempt to read the project's threat_detector output.
    The sample rows are clearly identified as demo fallback data.
    """
    records = []

    try:
        import threat_detector

        if hasattr(threat_detector, "run_lstm_inference"):
            results = threat_detector.run_lstm_inference() or []

            for index, result in enumerate(results):
                label = str(result)
                lower_label = label.lower()

                if "normal" in lower_label:
                    status = "NORMAL"
                    threat = "Normal"
                elif "ddos" in lower_label:
                    status = "CRITICAL"
                    threat = "DDoS"
                elif "bot" in lower_label:
                    status = "WARNING"
                    threat = "Bot"
                elif "port" in lower_label:
                    status = "WARNING"
                    threat = "PortScan"
                else:
                    status = "WARNING"
                    threat = label[:40] or "Unknown"

                records.append({
                    "IP": f"192.168.1.{34 + index}",
                    "Status": status,
                    "Threat": threat,
                    "Confidence": None,
                    "Acc": None,
                    "Source": "LSTM output",
                })

    except Exception as exc:
        print(f"[DETECTION ENGINE ERROR] {exc}")

    if records:
        return pd.DataFrame(records)

    # Demo data only: replace with actual threat_detector output for live use.
    return pd.DataFrame([
        {
            "IP": "192.168.1.34",
            "Status": "WARNING",
            "Threat": "Bot",
            "Confidence": 92.3,
            "Acc": 95.0,
            "Source": "Demo data",
        },
        {
            "IP": "192.168.1.76",
            "Status": "WARNING",
            "Threat": "Bot",
            "Confidence": 87.4,
            "Acc": 92.0,
            "Source": "Demo data",
        },
        {
            "IP": "192.168.1.96",
            "Status": "CRITICAL",
            "Threat": "DDoS",
            "Confidence": 95.8,
            "Acc": 98.0,
            "Source": "Demo data",
        },
        {
            "IP": "192.168.1.5",
            "Status": "WARNING",
            "Threat": "PortScan",
            "Confidence": 85.5,
            "Acc": 90.0,
            "Source": "Demo data",
        },
    ])


df = get_backend_predictions()

# Remove normal rows from the threat-focused dashboard table only if desired.
if df.empty:
    st.info("No prediction results are currently available.")

st.sidebar.divider()
st.sidebar.header("Filter & Controls")

threat_options = (
    sorted(df["Threat"].dropna().unique().tolist())
    if not df.empty else []
)
selected_threats = st.sidebar.multiselect(
    "Select Threat Types:",
    options=threat_options,
    default=threat_options,
)

filtered_df = (
    df[df["Threat"].isin(selected_threats)].copy()
    if not df.empty else df.copy()
)

st.sidebar.divider()
st.sidebar.subheader("🔴 Live Stream Simulation")
stream_live = st.sidebar.toggle(
    "Enable dashboard refresh",
    value=False,
)
if stream_live:
    st.sidebar.info(
        "Dashboard refresh simulation is enabled. "
        "This does not itself capture network packets."
    )
    time.sleep(1)
    st.rerun()


# ---------------------------------------------------------------------
# SOAR INCIDENT RESPONSE
# ---------------------------------------------------------------------
st.sidebar.divider()
st.sidebar.subheader("🛡️ Incident Response (SOAR)")

ip_options = (
    filtered_df["IP"].dropna().unique().tolist()
    if not filtered_df.empty else []
)
target_ip = st.sidebar.selectbox(
    "Select IP to review:",
    options=ip_options if ip_options else ["N/A"],
)

if st.sidebar.button("Record IP Isolation Action") and target_ip != "N/A":
    try:
        handle_security_event(
            (
                f"SOAR action requested: host {target_ip} selected for "
                f"firewall isolation by {st.session_state['username']}."
            ),
            is_critical=True,
        )
        st.sidebar.success(
            "Action recorded. Connect your authorized firewall controller "
            "to perform actual isolation."
        )
    except Exception as exc:
        st.sidebar.error(f"SOAR logging error: {exc}")


# ---------------------------------------------------------------------
# METRICS
# ---------------------------------------------------------------------
critical_count = (
    int((filtered_df["Status"] == "CRITICAL").sum())
    if not filtered_df.empty else 0
)
warning_count = (
    int((filtered_df["Status"] == "WARNING").sum())
    if not filtered_df.empty else 0
)
detected_count = critical_count + warning_count

metric1, metric2, metric3, metric4 = st.columns(4)
metric1.metric("Displayed Events", len(filtered_df))
metric2.metric("Critical Threats", critical_count)
metric3.metric("Warning Threats", warning_count)
metric4.metric("Detected Threats", detected_count)

st.divider()


# ---------------------------------------------------------------------
# VISUAL ANALYTICS
# ---------------------------------------------------------------------
chart1, chart2 = st.columns(2)

with chart1:
    st.subheader("📊 Threat Classification Breakdown")
    if not filtered_df.empty:
        threat_counts = (
            filtered_df["Threat"].value_counts()
            .rename_axis("Threat")
            .reset_index(name="Count")
        )
        pie = px.pie(
            threat_counts,
            values="Count",
            names="Threat",
            hole=0.4,
            color_discrete_sequence=px.colors.qualitative.Pastel,
        )
        pie.update_layout(
            margin=dict(t=20, b=20, l=20, r=20),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="white"),
        )
        st.plotly_chart(pie, use_container_width=True)
    else:
        st.info("No threat data available for the selected filters.")

with chart2:
    st.subheader("📈 Threat Confidence Scores")
    confidence_df = (
        filtered_df.dropna(subset=["Confidence"])
        if not filtered_df.empty and "Confidence" in filtered_df.columns
        else pd.DataFrame()
    )
    if not confidence_df.empty:
        bar = px.bar(
            confidence_df,
            x="IP",
            y="Confidence",
            color="Threat",
            title="Confidence level per IP address",
        )
        bar.update_layout(
            xaxis_tickangle=-45,
            margin=dict(t=30, b=40, l=20, r=20),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="white"),
        )
        st.plotly_chart(bar, use_container_width=True)
    else:
        st.info("The detector did not provide confidence scores.")


# ---------------------------------------------------------------------
# MODEL EXPLAINABILITY (DEMO FEATURE IMPORTANCE)
# ---------------------------------------------------------------------
st.divider()
st.subheader("🧠 Model Explainability & XAI")
st.caption(
    "Illustrative feature importance values. Replace these values with "
    "attributions calculated from your trained model."
)

xai_df = pd.DataFrame({
    "Feature": [
        "Packet Length Variance",
        "Flow Duration",
        "SYN Flag Count",
        "Header Length",
        "Inter-Arrival Time (IAT)",
        "Subflow Fwd Packets",
        "Destination Port",
    ],
    "Importance_Score": [28.4, 21.2, 16.5, 12.1, 9.8, 7.3, 4.7],
})

xai_col1, xai_col2 = st.columns([3, 2])

with xai_col1:
    xai_chart = px.bar(
        xai_df.sort_values("Importance_Score"),
        x="Importance_Score",
        y="Feature",
        orientation="h",
        title="Illustrative Packet Feature Importance",
        color="Importance_Score",
        color_continuous_scale="Reds",
    )
    xai_chart.update_layout(
        margin=dict(t=30, b=20, l=20, r=20),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="white"),
        showlegend=False,
    )
    st.plotly_chart(xai_chart, use_container_width=True)

with xai_col2:
    st.markdown("### 🔍 Diagnostic Insights")
    st.info(
        "The feature importance values currently shown are illustrative. "
        "Connect a model-specific explainability method before presenting "
        "them as measured LSTM explanations."
    )


# ---------------------------------------------------------------------
# THREAT INTELLIGENCE PLACEHOLDER
# ---------------------------------------------------------------------
st.divider()
st.subheader("🌐 External Threat Intelligence")

if not filtered_df.empty:
    selected_vt_ip = st.selectbox(
        "Select IP for reputation review:",
        options=filtered_df["IP"].unique().tolist(),
        key="vt_ip_select",
    )
    st.info(
        f"Selected IP: {selected_vt_ip}. "
        "Live VirusTotal/AbuseIPDB results are not configured in this version. "
        "Connect an authorized API key to display verified reputation data."
    )
else:
    st.info("No IP addresses are available for review.")


# ---------------------------------------------------------------------
# THREAT EVENT LOG
# ---------------------------------------------------------------------
st.divider()
st.subheader("🔍 Threat Detection Results")

if not filtered_df.empty:
    st.dataframe(
        filtered_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "IP": st.column_config.TextColumn("IP Address"),
            "Status": st.column_config.TextColumn("Status"),
            "Threat": st.column_config.TextColumn("Threat Category"),
            "Confidence": st.column_config.ProgressColumn(
                "Detection Confidence (%)",
                format="%.1f",
                min_value=0,
                max_value=100,
            ),
            "Acc": st.column_config.NumberColumn(
                "Model Accuracy (%)",
                format="%.1f",
            ),
        },
    )
else:
    st.info("No threat detection results to display.")


# ---------------------------------------------------------------------
# MANUAL THREAT ALERT TEST
# ---------------------------------------------------------------------
st.divider()
st.subheader("📧 Email Notification Test")

with st.expander("Send a test email to a registered user"):
    try:
        registered_emails = get_registered_user_emails()
    except Exception as exc:
        registered_emails = []
        st.error(f"Could not retrieve MySQL user emails: {exc}")

    if registered_emails:
        test_recipient = st.selectbox(
            "Choose registered recipient",
            registered_emails,
            key="test_email_recipient",
        )

        if st.button("Send Test Email"):
            test_body = """
            <html>
            <body style="font-family:Arial,sans-serif;">
                <h2 style="color:#ff4b4b;">Warisan Security Email Test</h2>
                <p>Your email notification configuration is working.</p>
                <p>This is a test message from the Warisan Security dashboard.</p>
            </body>
            </html>
            """
            sent, error = send_email_notification(
                test_recipient,
                "Warisan Security - Email Test",
                test_body,
                is_html=True,
            )
            if sent:
                st.success(f"Test email sent to {test_recipient}.")
            else:
                st.error(f"Test email failed: {error}")
    else:
        st.warning("No registered user email addresses were found in MySQL.")


# ---------------------------------------------------------------------
# EXPORT CSV AND PDF
# ---------------------------------------------------------------------
st.divider()
st.subheader("📥 Reports & Export")

download_col1, download_col2 = st.columns(2)

with download_col1:
    csv_bytes = filtered_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download CSV Report",
        data=csv_bytes,
        file_name="warisan_security_threat_report.csv",
        mime="text/csv",
        use_container_width=True,
    )

with download_col2:
    pdf_bytes = generate_pdf_report(filtered_df)
    st.download_button(
        "Download PDF Report",
        data=pdf_bytes,
        file_name="executive_threat_report.pdf",
        mime="application/pdf",
        use_container_width=True,
    )


# ---------------------------------------------------------------------
# ADMIN PDF BROADCAST
# ---------------------------------------------------------------------
user_role = str(st.session_state.get("role", "user")).strip().lower()

if user_role == "admin":
    st.divider()
    st.subheader("👑 Admin Controls")

    if st.button("📧 Email PDF Report to All Users"):
        try:
            recipients = get_registered_user_emails()

            if not recipients:
                st.warning("No registered user email addresses were found.")
            else:
                report_bytes = generate_pdf_report(filtered_df)
                sent_count = 0
                failed_count = 0

                progress = st.progress(0)
                status_text = st.empty()

                for index, recipient in enumerate(recipients, start=1):
                    success, error = send_email_with_attachment(
                        receiver_email=recipient,
                        subject=(
                            "[WARISAN SOC] Executive AI Threat "
                            "& Malware Operations Report"
                        ),
                        body=(
                            "Attached is the latest Warisan Security "
                            "Malware Operations report."
                        ),
                        attachment_bytes=report_bytes,
                    )

                    if success:
                        sent_count += 1
                    else:
                        failed_count += 1
                        print(f"[PDF EMAIL FAILED] {recipient}: {error}")

                    progress.progress(index / len(recipients))
                    status_text.write(
                        f"Processed {index} of {len(recipients)} recipients..."
                    )

                st.success(
                    f"PDF report sent to {sent_count} of "
                    f"{len(recipients)} registered users."
                )
                if failed_count:
                    st.warning(f"{failed_count} email(s) could not be sent.")

        except Exception as exc:
            st.error(f"PDF broadcast failed: {exc}")
else:
    st.caption(
        "🔒 Multi-user PDF broadcast is restricted to administrator accounts."
    )
'''
path = Path("/mnt/data/app.py")
path.write_text(code, encoding="utf-8")
compile(code, str(path), "exec")
print(f"Created {path} ({len(code.splitlines())} lines). Python syntax check: PASS.")
