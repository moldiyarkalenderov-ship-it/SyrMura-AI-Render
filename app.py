
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_file,
    abort,
    jsonify
)

from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from pathlib import Path
from datetime import datetime
import sqlite3
import secrets
import hmac
import os
import re


BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "database" / "syrmura.db"
UPLOAD_DIR = BASE_DIR / "uploads" / "documents"
SECRET_FILE = BASE_DIR / "secret_key.txt"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)


if os.environ.get("SECRET_KEY"):
    SECRET_KEY = os.environ["SECRET_KEY"]
elif SECRET_FILE.exists():
    SECRET_KEY = SECRET_FILE.read_text(
        encoding="utf-8"
    ).strip()
else:
    SECRET_KEY = secrets.token_hex(32)

    SECRET_FILE.write_text(
        SECRET_KEY,
        encoding="utf-8"
    )


app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static")
)

app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="None",
    MAX_CONTENT_LENGTH=50 * 1024 * 1024
)


ALLOWED_EXTENSIONS = {
    "jpg", "jpeg", "png", "gif", "webp",
    "pdf", "doc", "docx", "txt",
    "mp3", "wav", "mp4", "avi", "mov"
}


# ============================================================
# ДЕРЕКҚОР
# ============================================================

def get_db():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def rows_to_dicts(rows):
    return [dict(row) for row in rows]


def initialize_database():
    with get_db() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password_hash TEXT,
                role TEXT DEFAULT 'admin',
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                document_year INTEGER,
                section TEXT DEFAULT 'Мұрағат',
                subsection TEXT,
                description TEXT,
                source_name TEXT,
                source_url TEXT,
                original_filename TEXT,
                stored_filename TEXT,
                file_type TEXT,
                file_size INTEGER DEFAULT 0,
                status TEXT DEFAULT 'pending',
                created_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                return_reason TEXT,
                reviewed_by TEXT,
                reviewed_at TEXT,
                location_name TEXT,
                latitude REAL,
                longitude REAL
            )
            """
        )

        connection.commit()


initialize_database()


# ============================================================
# ҚАУІПСІЗДІК
# ============================================================

def csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)

    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


def valid_csrf():
    session_token = session.get("_csrf_token", "")
    form_token = request.form.get("csrf_token", "")

    return bool(
        session_token
        and form_token
        and hmac.compare_digest(
            str(session_token),
            str(form_token)
        )
    )


def admin_required(function):
    @wraps(function)
    def protected_function(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(
                url_for(
                    "admin_login_v4",
                    next=request.path
                )
            )

        return function(*args, **kwargs)

    return protected_function


def current_admin():
    return (
        session.get("admin_username")
        or session.get("admin_email")
        or "Әкімші"
    )


def safe_coordinate(value, minimum, maximum):
    if value is None:
        return None

    value = str(value).strip().replace(",", ".")

    if not value:
        return None

    try:
        number = float(value)
    except (TypeError, ValueError):
        return None

    if minimum <= number <= maximum:
        return number

    return None


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


def unique_filename(original_filename):
    extension = (
        original_filename.rsplit(".", 1)[1].lower()
        if "." in original_filename
        else "bin"
    )

    return (
        datetime.now().strftime("%Y%m%d_%H%M%S_")
        + secrets.token_hex(6)
        + "."
        + extension
    )


def document_path(document):
    stored_filename = document["stored_filename"]

    if not stored_filename:
        return None

    possible_paths = [
        UPLOAD_DIR / stored_filename,
        BASE_DIR / "uploads" / stored_filename,
        BASE_DIR / "static" / "images" / stored_filename
    ]

    for path in possible_paths:
        if path.exists() and path.is_file():
            return path

    return None


# ============================================================
# БАСТЫ БЕТ
# ============================================================

@app.route("/")
def home_v4():
    with get_db() as connection:
        documents = rows_to_dicts(
            connection.execute(
                """
                SELECT *
                FROM documents
                WHERE status = 'published'
                ORDER BY id DESC
                LIMIT 8
                """
            ).fetchall()
        )

    return render_template(
        "index.html",
        documents=documents,
        archive_documents=documents
    )


@app.route("/digitization")
def digitization_v4():
    return render_template("digitization.html")


# ============================================================
# ӘКІМШІГЕ КІРУ
# ============================================================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login_v4():
    error = None

    if request.method == "POST":
        username = request.form.get(
            "username", ""
        ).strip()

        password = request.form.get(
            "password", ""
        )

        with get_db() as connection:
            user = connection.execute(
                """
                SELECT *
                FROM users
                WHERE username = ?
                  AND is_active = 1
                """,
                (username,)
            ).fetchone()

        authenticated = False

        if user:
            stored_password = user["password_hash"] or ""

            try:
                authenticated = check_password_hash(
                    stored_password,
                    password
                )
            except Exception:
                authenticated = hmac.compare_digest(
                    stored_password,
                    password
                )

        if authenticated:
            session.clear()
            session["admin_logged_in"] = True
            session["admin_username"] = username
            session["admin_email"] = username
            session["is_admin"] = True
            csrf_token()

            next_page = request.args.get("next")

            if (
                next_page
                and next_page.startswith("/")
                and not next_page.startswith("//")
            ):
                return redirect(next_page)

            return redirect(
                url_for("admin_dashboard_v4")
            )

        error = "Логин немесе құпиясөз дұрыс емес."

    return render_template(
        "admin_login.html",
        error=error
    )


@app.route("/admin/logout")
def admin_logout_v4():
    session.clear()
    return redirect(url_for("home_v4"))


# ============================================================
# ӘКІМШІ ПАНЕЛІ
# ============================================================

@app.route("/admin")
@admin_required
def admin_dashboard_v4():
    with get_db() as connection:
        counts = {}

        for status in [
            "pending",
            "published",
            "returned"
        ]:
            counts[status] = connection.execute(
                """
                SELECT COUNT(*)
                FROM documents
                WHERE status = ?
                """,
                (status,)
            ).fetchone()[0]

        total_count = connection.execute(
            "SELECT COUNT(*) FROM documents"
        ).fetchone()[0]

    return render_template(
        "admin_dashboard.html",
        admin_username=current_admin(),
        username=current_admin(),
        total_count=total_count,
        total_documents=total_count,
        pending_count=counts["pending"],
        published_count=counts["published"],
        returned_count=counts["returned"],
        stats={
            "total": total_count,
            "pending": counts["pending"],
            "published": counts["published"],
            "returned": counts["returned"]
        }
    )


# ============================================================
# ҚҰЖАТ ЖҮКТЕУ
# ============================================================

@app.route("/admin/upload", methods=["GET", "POST"])
@admin_required
def admin_upload_v4():
    if request.method == "POST":
        if not valid_csrf():
            flash(
                "Қауіпсіздік токені жарамсыз. "
                "Бетті жаңартып, қайталап көріңіз.",
                "error"
            )
            return redirect(
                url_for("admin_upload_v4")
            )

        title = request.form.get(
            "title", ""
        ).strip()

        uploaded_file = request.files.get(
            "document_file"
        )

        if not title:
            flash(
                "Құжат атауын енгізіңіз.",
                "error"
            )
            return redirect(
                url_for("admin_upload_v4")
            )

        if (
            uploaded_file is None
            or not uploaded_file.filename
        ):
            flash(
                "Құжат файлын таңдаңыз.",
                "error"
            )
            return redirect(
                url_for("admin_upload_v4")
            )

        if not allowed_file(uploaded_file.filename):
            flash(
                "Бұл файл түрін жүктеуге болмайды.",
                "error"
            )
            return redirect(
                url_for("admin_upload_v4")
            )

        original_filename = secure_filename(
            uploaded_file.filename
        )

        stored_filename = unique_filename(
            original_filename
        )

        saved_path = UPLOAD_DIR / stored_filename
        uploaded_file.save(saved_path)

        document_year = request.form.get(
            "document_year", ""
        ).strip()

        try:
            document_year = (
                int(document_year)
                if document_year
                else None
            )
        except ValueError:
            document_year = None

        latitude = safe_coordinate(
            request.form.get("latitude"),
            -90,
            90
        )

        longitude = safe_coordinate(
            request.form.get("longitude"),
            -180,
            180
        )

        with get_db() as connection:
            connection.execute(
                """
                INSERT INTO documents (
                    title,
                    document_year,
                    section,
                    subsection,
                    description,
                    source_name,
                    source_url,
                    original_filename,
                    stored_filename,
                    file_type,
                    file_size,
                    status,
                    created_by,
                    location_name,
                    latitude,
                    longitude
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        'pending', ?, ?, ?, ?)
                """,
                (
                    title,
                    document_year,
                    request.form.get(
                        "section", "Мұрағат"
                    ).strip() or "Мұрағат",
                    request.form.get(
                        "subsection", ""
                    ).strip(),
                    request.form.get(
                        "description", ""
                    ).strip(),
                    request.form.get(
                        "source_name", ""
                    ).strip(),
                    request.form.get(
                        "source_url", ""
                    ).strip(),
                    original_filename,
                    stored_filename,
                    saved_path.suffix.lower(),
                    saved_path.stat().st_size,
                    current_admin(),
                    request.form.get(
                        "location_name", ""
                    ).strip(),
                    latitude,
                    longitude
                )
            )

            connection.commit()

        flash(
            "Құжат сақталды және тексеруге жіберілді.",
            "success"
        )

        return redirect(
            url_for("admin_pending")
        )

    return render_template("admin_upload.html")


# ============================================================
# ҚҰЖАТТАРДЫ ТЕКСЕРУ
# ============================================================

def render_documents_page(
    status,
    title,
    description
):
    with get_db() as connection:
        documents = rows_to_dicts(
            connection.execute(
                """
                SELECT *
                FROM documents
                WHERE status = ?
                ORDER BY id DESC
                """,
                (status,)
            ).fetchall()
        )

    return render_template(
        "admin_documents.html",
        documents=documents,
        current_status=status,
        page_title=title,
        page_description=description,
        admin_username=current_admin(),
        review_csrf=csrf_token()
    )


@app.route("/admin/documents/pending")
@admin_required
def admin_pending():
    return render_documents_page(
        "pending",
        "Тексеруді күтудегі құжаттар",
        "Жүктелген материалдарды қарап, "
        "жариялаңыз немесе түзетуге қайтарыңыз."
    )


@app.route("/admin/documents/published")
@admin_required
def admin_published():
    return render_documents_page(
        "published",
        "Жарияланған құжаттар",
        "Әкімші жариялауға рұқсат берген материалдар."
    )


@app.route("/admin/documents/returned")
@admin_required
def admin_returned():
    return render_documents_page(
        "returned",
        "Түзетуге қайтарылған құжаттар",
        "Толықтыру немесе түзету қажет материалдар."
    )


@app.route(
    "/admin/document/<int:document_id>/approve",
    methods=["POST"]
)
@admin_required
def admin_document_approve(document_id):
    if not valid_csrf():
        abort(400, "CSRF токені жарамсыз")

    with get_db() as connection:
        connection.execute(
            """
            UPDATE documents
            SET status = 'published',
                return_reason = NULL,
                reviewed_by = ?,
                reviewed_at = ?
            WHERE id = ?
            """,
            (
                current_admin(),
                datetime.now().isoformat(
                    timespec="seconds"
                ),
                document_id
            )
        )

        connection.commit()

    flash("Құжат жарияланды.", "success")
    return redirect(url_for("admin_pending"))


@app.route(
    "/admin/document/<int:document_id>/return",
    methods=["POST"]
)
@admin_required
def admin_document_return(document_id):
    if not valid_csrf():
        abort(400, "CSRF токені жарамсыз")

    return_reason = request.form.get(
        "return_reason", ""
    ).strip()

    with get_db() as connection:
        connection.execute(
            """
            UPDATE documents
            SET status = 'returned',
                return_reason = ?,
                reviewed_by = ?,
                reviewed_at = ?
            WHERE id = ?
            """,
            (
                return_reason,
                current_admin(),
                datetime.now().isoformat(
                    timespec="seconds"
                ),
                document_id
            )
        )

        connection.commit()

    flash(
        "Құжат түзетуге қайтарылды.",
        "success"
    )

    return redirect(url_for("admin_pending"))


# ============================================================
# ҚҰЖАТТЫ ӨҢДЕУ ЖӘНЕ ЖОЮ
# ============================================================

@app.route(
    "/admin/document/<int:document_id>/edit",
    methods=["GET", "POST"]
)
@admin_required
def admin_document_edit(document_id):
    with get_db() as connection:
        document = connection.execute(
            """
            SELECT *
            FROM documents
            WHERE id = ?
            """,
            (document_id,)
        ).fetchone()

        if document is None:
            abort(404)

        if request.method == "POST":
            if not valid_csrf():
                abort(400, "CSRF токені жарамсыз")

            year_value = request.form.get(
                "document_year", ""
            ).strip()

            try:
                year_value = (
                    int(year_value)
                    if year_value
                    else None
                )
            except ValueError:
                year_value = None

            connection.execute(
                """
                UPDATE documents
                SET title = ?,
                    section = ?,
                    subsection = ?,
                    document_year = ?,
                    source_name = ?,
                    source_url = ?,
                    description = ?,
                    location_name = ?,
                    latitude = ?,
                    longitude = ?
                WHERE id = ?
                """,
                (
                    request.form.get(
                        "title", ""
                    ).strip(),
                    request.form.get(
                        "section", "Мұрағат"
                    ).strip(),
                    request.form.get(
                        "subsection", ""
                    ).strip(),
                    year_value,
                    request.form.get(
                        "source_name", ""
                    ).strip(),
                    request.form.get(
                        "source_url", ""
                    ).strip(),
                    request.form.get(
                        "description", ""
                    ).strip(),
                    request.form.get(
                        "location_name", ""
                    ).strip(),
                    safe_coordinate(
                        request.form.get("latitude"),
                        -90,
                        90
                    ),
                    safe_coordinate(
                        request.form.get("longitude"),
                        -180,
                        180
                    ),
                    document_id
                )
            )

            connection.commit()

            flash(
                "Құжат мәліметтері жаңартылды.",
                "success"
            )

            return redirect(
                url_for("admin_published")
            )

    return render_template(
        "admin_edit_document.html",
        document=dict(document),
        doc=dict(document)
    )


@app.route(
    "/admin/document/<int:document_id>/delete",
    methods=["POST"]
)
@admin_required
def admin_document_delete(document_id):
    if not valid_csrf():
        abort(400, "CSRF токені жарамсыз")

    with get_db() as connection:
        document = connection.execute(
            """
            SELECT *
            FROM documents
            WHERE id = ?
            """,
            (document_id,)
        ).fetchone()

        if document is None:
            abort(404)

        file_path = document_path(document)

        connection.execute(
            "DELETE FROM documents WHERE id = ?",
            (document_id,)
        )

        connection.commit()

    if file_path and file_path.exists():
        file_path.unlink()

    flash("Құжат жойылды.", "success")
    return redirect(url_for("admin_published"))


# ============================================================
# ҚҰЖАТ ФАЙЛДАРЫ
# ============================================================

@app.route(
    "/admin/document/<int:document_id>/file"
)
@admin_required
def admin_document_file(document_id):
    with get_db() as connection:
        document = connection.execute(
            """
            SELECT *
            FROM documents
            WHERE id = ?
            """,
            (document_id,)
        ).fetchone()

    if document is None:
        abort(404)

    file_path = document_path(document)

    if file_path is None:
        abort(404)

    return send_file(
        file_path,
        as_attachment=False,
        download_name=document["original_filename"]
    )


@app.route(
    "/archive/file/<int:document_id>"
)
def public_document_file(document_id):
    with get_db() as connection:
        document = connection.execute(
            """
            SELECT *
            FROM documents
            WHERE id = ?
              AND status = 'published'
            """,
            (document_id,)
        ).fetchone()

    if document is None:
        abort(404)

    file_path = document_path(document)

    if file_path is None:
        abort(404)

    return send_file(
        file_path,
        as_attachment=False,
        download_name=document["original_filename"]
    )


# ============================================================
# КООРДИНАТ API
# ============================================================

@app.route(
    "/admin/document-location/<int:document_id>"
)
@admin_required
def admin_document_location(document_id):
    with get_db() as connection:
        document = connection.execute(
            """
            SELECT id, location_name,
                   latitude, longitude
            FROM documents
            WHERE id = ?
            """,
            (document_id,)
        ).fetchone()

    if document is None:
        return jsonify({
            "success": False
        }), 404

    return jsonify({
        "success": True,
        "document_id": document["id"],
        "location_name":
            document["location_name"] or "",
        "latitude": document["latitude"],
        "longitude": document["longitude"]
    })


# ============================================================
# ҚОҒАМДЫҚ МҰРАҒАТ
# ============================================================

@app.route("/archive")
def public_archive():
    query = request.args.get(
        "q", ""
    ).strip()

    subsection = (
        request.args.get("subsection")
        or request.args.get("section")
        or ""
    ).strip()

    conditions = ["status = 'published'"]
    parameters = []

    if query:
        conditions.append(
            """
            (
                title LIKE ?
                OR description LIKE ?
                OR source_name LIKE ?
                OR location_name LIKE ?
            )
            """
        )

        search_value = f"%{query}%"
        parameters.extend(
            [search_value] * 4
        )

    if subsection:
        conditions.append("subsection = ?")
        parameters.append(subsection)

    where_sql = " AND ".join(conditions)

    with get_db() as connection:
        documents = rows_to_dicts(
            connection.execute(
                f"""
                SELECT *
                FROM documents
                WHERE {where_sql}
                ORDER BY document_year, id DESC
                """,
                parameters
            ).fetchall()
        )

        subsection_rows = connection.execute(
            """
            SELECT DISTINCT subsection
            FROM documents
            WHERE status = 'published'
              AND subsection IS NOT NULL
              AND subsection != ''
            ORDER BY subsection
            """
        ).fetchall()

    subsections = [
        row["subsection"]
        for row in subsection_rows
    ]

    grouped_documents = {}

    for document in documents:
        group_name = (
            document.get("subsection")
            or "Басқа материалдар"
        )

        grouped_documents.setdefault(
            group_name, []
        ).append(document)

    return render_template(
        "archive.html",
        documents=documents,
        grouped_documents=grouped_documents,
        subsections=subsections,
        sections=subsections,
        selected_subsection=subsection,
        selected_section=subsection,
        current_subsection=subsection,
        q=query,
        query=query
    )


# ============================================================
# ЖИ АРХИВШІ
# ============================================================

def search_score(document, keywords):
    text = " ".join([
        str(document.get("title") or ""),
        str(document.get("description") or ""),
        str(document.get("document_year") or ""),
        str(document.get("source_name") or ""),
        str(document.get("section") or ""),
        str(document.get("subsection") or ""),
        str(document.get("location_name") or "")
    ]).lower()

    return sum(
        text.count(keyword)
        for keyword in keywords
    )


@app.route("/ai-archivist")
def ai_archivist():
    question = request.args.get(
        "q", ""
    ).strip()

    results = []
    answer = None

    if question:
        keywords = [
            word.lower()
            for word in re.findall(
                r"[A-Za-zА-Яа-яӘәІіҢңҒғҮүҰұҚқӨөҺһ0-9]+",
                question
            )
            if len(word) >= 3
        ]

        with get_db() as connection:
            documents = rows_to_dicts(
                connection.execute(
                    """
                    SELECT *
                    FROM documents
                    WHERE status = 'published'
                    """
                ).fetchall()
            )

        scored_documents = []

        for document in documents:
            score = search_score(
                document,
                keywords
            )

            if score > 0:
                document["search_score"] = score
                document["file_url"] = url_for(
                    "public_document_file",
                    document_id=document["id"]
                )

                scored_documents.append(document)

        results = sorted(
            scored_documents,
            key=lambda item: (
                -item["search_score"],
                item.get("document_year") or 9999
            )
        )[:5]

        if results:
            first = results[0]

            answer = (
                f"Архивтен «{first['title']}» материалы табылды. "
                f"{first.get('description') or 'Құжат сипаттамасы берілмеген.'} "
                f"Дереккөз: "
                f"{first.get('source_name') or 'архив қоры'}."
            )
        else:
            answer = (
                "Жарияланған архив материалдарының ішінен "
                "сұраққа сәйкес дерек табылмады."
            )

    return render_template(
        "ai_archivist.html",
        q=question,
        question=question,
        answer=answer,
        results=results,
        documents=results
    )


# ============================================================
# УАҚЫТ ЖЕЛІСІ
# ============================================================

@app.route("/timeline")
def public_timeline():
    query = request.args.get(
        "q", ""
    ).strip()

    subsection = request.args.get(
        "subsection", ""
    ).strip()

    conditions = [
        "status = 'published'",
        "document_year IS NOT NULL"
    ]

    parameters = []

    if query:
        conditions.append(
            "(title LIKE ? OR description LIKE ?)"
        )

        search_value = f"%{query}%"
        parameters.extend(
            [search_value, search_value]
        )

    if subsection:
        conditions.append("subsection = ?")
        parameters.append(subsection)

    with get_db() as connection:
        documents = rows_to_dicts(
            connection.execute(
                f"""
                SELECT *
                FROM documents
                WHERE {' AND '.join(conditions)}
                ORDER BY document_year, id
                """,
                parameters
            ).fetchall()
        )

        subsection_rows = connection.execute(
            """
            SELECT DISTINCT subsection
            FROM documents
            WHERE status = 'published'
              AND subsection IS NOT NULL
              AND subsection != ''
            ORDER BY subsection
            """
        ).fetchall()

    subsections = [
        row["subsection"]
        for row in subsection_rows
    ]

    return render_template(
        "timeline.html",
        documents=documents,
        timeline_documents=documents,
        subsections=subsections,
        q=query,
        query=query,
        selected_subsection=subsection
    )


# ============================================================
# АРХИВ КАРТАСЫ
# ============================================================

@app.route("/archive-map")
def archive_map():
    with get_db() as connection:
        documents = rows_to_dicts(
            connection.execute(
                """
                SELECT *
                FROM documents
                WHERE status = 'published'
                  AND latitude IS NOT NULL
                  AND longitude IS NOT NULL
                ORDER BY document_year, title
                """
            ).fetchall()
        )

    for document in documents:
        document["file_url"] = url_for(
            "public_document_file",
            document_id=document["id"]
        )

    subsections = sorted({
        document.get("subsection") or "Мұрағат"
        for document in documents
    })

    return render_template(
        "archive_map.html",
        documents=documents,
        subsections=subsections
    )




# SYRMURA_VIRTUAL_EXHIBITION_ROUTE
@app.route("/virtual-exhibition")
def virtual_exhibition():
    image_extensions = (
        ".jpg", ".jpeg", ".png",
        ".gif", ".webp"
    )

    with get_db() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM documents
            WHERE status = 'published'
            ORDER BY
                CASE
                    WHEN document_year IS NULL THEN 1
                    ELSE 0
                END,
                document_year,
                id DESC
            """
        ).fetchall()

    documents = []

    for row in rows:
        document = dict(row)

        stored_filename = str(
            document.get("stored_filename") or ""
        ).lower()

        file_type = str(
            document.get("file_type") or ""
        ).lower()

        is_image = (
            stored_filename.endswith(image_extensions)
            or file_type in {
                ".jpg", ".jpeg", ".png",
                ".gif", ".webp",
                "jpg", "jpeg", "png",
                "gif", "webp",
                "image/jpeg", "image/png",
                "image/gif", "image/webp"
            }
        )

        if not is_image:
            continue

        document["file_url"] = url_for(
            "public_document_file",
            document_id=document["id"]
        )

        documents.append(document)

    subsections = sorted({
        document.get("subsection") or "Басқа"
        for document in documents
    })

    return render_template(
        "virtual_exhibition.html",
        documents=documents,
        subsections=subsections
    )




# SYRMURA_QR_SYSTEM_ROUTES
@app.route("/qr-gallery")
def qr_gallery():
    with get_db() as connection:
        documents = rows_to_dicts(
            connection.execute(
                """
                SELECT *
                FROM documents
                WHERE status = 'published'
                ORDER BY document_year, id DESC
                """
            ).fetchall()
        )

    return render_template(
        "qr_gallery.html",
        documents=documents
    )


@app.route("/archive/qr/<int:document_id>")
def document_qr_code(document_id):
    from io import BytesIO
    import qrcode

    with get_db() as connection:
        document = connection.execute(
            """
            SELECT *
            FROM documents
            WHERE id = ?
              AND status = 'published'
            """,
            (document_id,)
        ).fetchone()

    if document is None:
        abort(404)

    material_url = (
        request.url_root.rstrip("/")
        + url_for(
            "public_document_file",
            document_id=document_id
        )
    )

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4
    )

    qr.add_data(material_url)
    qr.make(fit=True)

    qr_image = qr.make_image(
        fill_color="#071b33",
        back_color="white"
    )

    image_buffer = BytesIO()
    qr_image.save(
        image_buffer,
        format="PNG"
    )

    image_buffer.seek(0)

    download_requested = (
        request.args.get("download") == "1"
    )

    return send_file(
        image_buffer,
        mimetype="image/png",
        as_attachment=download_requested,
        download_name=(
            f"syrmura_qr_{document_id}.png"
        )
    )




# SYRMURA_OCR_ROUTE
@app.route("/ocr", methods=["GET", "POST"])
@admin_required
def ocr_recognition():
    from PIL import (
        Image,
        ImageEnhance,
        ImageFilter,
        ImageOps
    )

    import pytesseract

    result = None
    error = None
    filename = None

    if request.method == "POST":
        if not valid_csrf():
            error = (
                "Қауіпсіздік токені жарамсыз. "
                "Бетті жаңартып, қайта орындаңыз."
            )

            return render_template(
                "ocr.html",
                result=result,
                error=error,
                filename=filename
            )

        uploaded_image = request.files.get(
            "ocr_image"
        )

        selected_language = request.form.get(
            "ocr_language",
            "kaz+rus+eng"
        )

        allowed_ocr_languages = {
            "kaz",
            "rus",
            "eng",
            "kaz+rus",
            "kaz+rus+eng"
        }

        if selected_language not in allowed_ocr_languages:
            selected_language = "kaz+rus+eng"

        if (
            uploaded_image is None
            or not uploaded_image.filename
        ):
            error = "Құжат суретін таңдаңыз."

        else:
            filename = secure_filename(
                uploaded_image.filename
            )

            allowed_extensions = {
                "jpg", "jpeg", "png",
                "tif", "tiff"
            }

            extension = (
                filename.rsplit(".", 1)[1].lower()
                if "." in filename
                else ""
            )

            if extension not in allowed_extensions:
                error = (
                    "OCR үшін JPG, PNG немесе TIFF "
                    "файлын жүктеңіз."
                )

            else:
                try:
                    image = Image.open(
                        uploaded_image.stream
                    )

                    # Түпнұсқа сурет өзгермейді:
                    # өңдеу жадтағы көшірмеге жасалады
                    processed_image = image.copy()

                    if processed_image.mode not in (
                        "RGB",
                        "L"
                    ):
                        processed_image = (
                            processed_image.convert("RGB")
                        )

                    # Сұр түске айналдыру
                    processed_image = ImageOps.grayscale(
                        processed_image
                    )

                    # Сурет тым кішкентай болса үлкейту
                    minimum_width = 1600

                    if processed_image.width < minimum_width:
                        scale = (
                            minimum_width
                            / processed_image.width
                        )

                        new_size = (
                            int(
                                processed_image.width
                                * scale
                            ),
                            int(
                                processed_image.height
                                * scale
                            )
                        )

                        processed_image = (
                            processed_image.resize(
                                new_size
                            )
                        )

                    # Контраст пен айқындықты арттыру
                    processed_image = ImageEnhance.Contrast(
                        processed_image
                    ).enhance(1.8)

                    processed_image = (
                        processed_image.filter(
                            ImageFilter.SHARPEN
                        )
                    )

                    installed_languages = set(
                        pytesseract.get_languages(
                            config=""
                        )
                    )

                    requested_languages = (
                        selected_language.split("+")
                    )

                    usable_languages = [
                        language
                        for language in requested_languages
                        if language in installed_languages
                    ]

                    if not usable_languages:
                        usable_languages = ["eng"]

                    ocr_language = "+".join(
                        usable_languages
                    )

                    result = pytesseract.image_to_string(
                        processed_image,
                        lang=ocr_language,
                        config="--oem 3 --psm 6"
                    ).strip()

                    if not result:
                        error = (
                            "Суреттен мәтін табылмады. "
                            "Анығырақ сканерленген файлды қолданыңыз."
                        )

                except Exception as recognition_error:
                    error = (
                        "Мәтінді тану кезінде қате шықты: "
                        + str(recognition_error)
                    )

    return render_template(
        "ocr.html",
        result=result,
        error=error,
        filename=filename
    )




# SYRMURA_QUALITY_CHECK_ROUTE
@app.route("/quality-check", methods=["GET", "POST"])
@admin_required
def quality_check():
    from PIL import (
        Image,
        ImageOps,
        ImageStat,
        ImageFilter
    )

    from io import BytesIO
    import base64
    import math

    report = None
    error = None
    preview_data = None

    def clamp(value, minimum=0, maximum=100):
        return max(
            minimum,
            min(maximum, int(round(value)))
        )

    if request.method == "POST":
        if not valid_csrf():
            error = (
                "Қауіпсіздік токені жарамсыз. "
                "Бетті жаңартып қайталаңыз."
            )

        else:
            uploaded_file = request.files.get(
                "quality_image"
            )

            if (
                uploaded_file is None
                or not uploaded_file.filename
            ):
                error = "Құжат суретін таңдаңыз."

            else:
                try:
                    image = Image.open(
                        uploaded_file.stream
                    )

                    image.load()

                    if image.mode not in ("RGB", "L"):
                        image = image.convert("RGB")

                    preview_image = image.copy()
                    preview_image.thumbnail((900, 900))

                    preview_buffer = BytesIO()

                    if preview_image.mode == "L":
                        preview_image = (
                            preview_image.convert("RGB")
                        )

                    preview_image.save(
                        preview_buffer,
                        format="JPEG",
                        quality=85
                    )

                    preview_data = (
                        "data:image/jpeg;base64,"
                        + base64.b64encode(
                            preview_buffer.getvalue()
                        ).decode("ascii")
                    )

                    grayscale = ImageOps.grayscale(image)

                    width, height = grayscale.size
                    minimum_dimension = min(width, height)
                    total_pixels = width * height

                    # 1. Ажыратымдылық
                    resolution_score = clamp(
                        (
                            minimum_dimension / 1600
                        ) * 70
                        +
                        (
                            total_pixels
                            / 3000000
                        ) * 30
                    )

                    # 2. Контраст
                    grayscale_stat = ImageStat.Stat(
                        grayscale
                    )

                    brightness = (
                        grayscale_stat.mean[0]
                    )

                    contrast_value = (
                        grayscale_stat.stddev[0]
                    )

                    contrast_score = clamp(
                        (
                            contrast_value / 60
                        ) * 100
                    )

                    # 3. Жарық
                    # 128 шамасына жақын болса жоғары балл
                    brightness_distance = abs(
                        brightness - 140
                    )

                    brightness_score = clamp(
                        100
                        - brightness_distance * 1.25
                    )

                    # 4. Анықтық
                    analysis_image = grayscale.copy()
                    analysis_image.thumbnail(
                        (1400, 1400)
                    )

                    edges = analysis_image.filter(
                        ImageFilter.FIND_EDGES
                    )

                    edge_stat = ImageStat.Stat(edges)
                    edge_mean = edge_stat.mean[0]
                    edge_deviation = (
                        edge_stat.stddev[0]
                    )

                    sharpness_value = (
                        edge_mean * 0.5
                        + edge_deviation
                    )

                    sharpness_score = clamp(
                        (
                            sharpness_value / 45
                        ) * 100
                    )

                    total_score = clamp(
                        resolution_score * 0.25
                        + sharpness_score * 0.35
                        + contrast_score * 0.25
                        + brightness_score * 0.15
                    )

                    if total_score >= 85:
                        grade = "Өте жақсы"
                        color = "#23965d"
                        summary = (
                            "Құжат сапасы архивке сақтауға "
                            "және OCR мәтін тануға қолайлы."
                        )

                    elif total_score >= 70:
                        grade = "Жақсы"
                        color = "#2488bb"
                        summary = (
                            "Құжат сапасы жеткілікті, бірақ "
                            "кейбір көрсеткішті жақсартуға болады."
                        )

                    elif total_score >= 50:
                        grade = "Орташа"
                        color = "#d18a22"
                        summary = (
                            "Құжатты пайдалануға болады, алайда "
                            "OCR нәтижесінде қателер болуы мүмкін."
                        )

                    else:
                        grade = "Төмен"
                        color = "#c5474e"
                        summary = (
                            "Құжатты қайта сканерлеу ұсынылады."
                        )

                    recommendations = []

                    if resolution_score < 70:
                        recommendations.append(
                            "Құжатты кемінде 300 DPI "
                            "ажыратымдылықпен қайта сканерлеңіз."
                        )

                    if sharpness_score < 70:
                        recommendations.append(
                            "Камераны немесе құжатты қозғалтпай, "
                            "фокусты мәтінге дәл келтіріңіз."
                        )

                    if contrast_score < 65:
                        recommendations.append(
                            "Мәтін мен фонның контрастын "
                            "арттырыңыз."
                        )

                    if brightness_score < 65:
                        if brightness < 100:
                            recommendations.append(
                                "Құжат тым қараңғы. "
                                "Жарықты көбейтіңіз."
                            )
                        else:
                            recommendations.append(
                                "Құжат тым жарық. "
                                "Жарықты немесе экспозицияны азайтыңыз."
                            )

                    if not recommendations:
                        recommendations.append(
                            "Құжат сапасы жақсы. "
                            "Оны OCR мәтін тануға жіберуге болады."
                        )

                    report = {
                        "total_score": total_score,
                        "grade": grade,
                        "color": color,
                        "summary": summary,
                        "metrics": [
                            {
                                "name": "Ажыратымдылық",
                                "score": resolution_score,
                                "note": (
                                    f"{width} × {height} пиксель"
                                )
                            },
                            {
                                "name": "Анықтық",
                                "score": sharpness_score,
                                "note": (
                                    "Мәтін шеттерінің "
                                    "айқындық көрсеткіші"
                                )
                            },
                            {
                                "name": "Контраст",
                                "score": contrast_score,
                                "note": (
                                    f"Контраст мәні: "
                                    f"{contrast_value:.1f}"
                                )
                            },
                            {
                                "name": "Жарық",
                                "score": brightness_score,
                                "note": (
                                    f"Орташа жарық мәні: "
                                    f"{brightness:.1f}"
                                )
                            }
                        ],
                        "recommendations":
                            recommendations
                    }

                except Exception as analysis_error:
                    error = (
                        "Суретті талдау мүмкін болмады: "
                        + str(analysis_error)
                    )

    return render_template(
        "quality_check.html",
        report=report,
        error=error,
        preview_data=preview_data
    )


# ============================================================
# ҚАТЕЛЕРДІ ӨҢДЕУ
# ============================================================

@app.errorhandler(400)
def bad_request(error):
    return (
        "Сұранысты орындау мүмкін болмады: "
        + str(error),
        400
    )


@app.errorhandler(404)
def page_not_found(error):
    return (
        "Сұралған бет немесе файл табылмады.",
        404
    )


@app.errorhandler(500)
def internal_error(error):
    return (
        "Сервер қатесі анықталды. "
        "Толық ақпарат журналға жазылды.",
        500
    )




# === DOCUMENT RESTORATION FEATURE V1 ===

from pathlib import Path as _RestorationPath
from functools import wraps as _restoration_wraps
from flask import (
    request as _restoration_request,
    render_template as _restoration_render_template,
    redirect as _restoration_redirect,
    url_for as _restoration_url_for,
    session as _restoration_session,
    flash as _restoration_flash,
    send_from_directory as _restoration_send_from_directory
)
from werkzeug.utils import secure_filename as _restoration_secure_filename
from PIL import (
    Image as _RestorationImage,
    ImageEnhance as _RestorationEnhance,
    ImageFilter as _RestorationFilter,
    ImageOps as _RestorationOps
)
import secrets as _restoration_secrets
import time as _restoration_time


_RESTORATION_ROOT = _RestorationPath(app.root_path)

_RESTORATION_TEMP = (
    _RESTORATION_ROOT /
    "static" /
    "restoration_uploads"
)

_RESTORATION_OUTPUT = (
    _RESTORATION_ROOT /
    "static" /
    "restored_documents"
)

_RESTORATION_TEMP.mkdir(
    parents=True,
    exist_ok=True
)

_RESTORATION_OUTPUT.mkdir(
    parents=True,
    exist_ok=True
)

_RESTORATION_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".tif",
    ".tiff"
}


def _restoration_admin_required(function):

    @_restoration_wraps(function)
    def protected(*args, **kwargs):

        logged_in = (
            _restoration_session.get(
                "admin_logged_in"
            )
            or
            _restoration_session.get(
                "is_admin"
            )
        )

        if not logged_in:
            _restoration_flash(
                "Алдымен әкімші жүйесіне кіріңіз.",
                "error"
            )

            return _restoration_redirect(
                _restoration_url_for(
                    "admin_login_v4"
                )
            )

        return function(*args, **kwargs)

    return protected


def _get_restoration_csrf():

    token = _restoration_session.get(
        "_restoration_csrf"
    )

    if not token:
        token = _restoration_secrets.token_hex(24)

        _restoration_session[
            "_restoration_csrf"
        ] = token

    return token


@app.route(
    "/document-restoration",
    methods=["GET", "POST"],
    endpoint="document_restoration"
)
@_restoration_admin_required
def document_restoration():

    original_url = None
    restored_url = None
    download_url = None

    restoration_csrf = (
        _get_restoration_csrf()
    )

    if _restoration_request.method == "POST":

        submitted_token = (
            _restoration_request.form.get(
                "restoration_csrf",
                ""
            )
        )

        if not _restoration_secrets.compare_digest(
            submitted_token,
            restoration_csrf
        ):
            _restoration_flash(
                "Қауіпсіздік таңбасы жарамсыз. "
                "Бетті жаңартып, қайталап көріңіз.",
                "error"
            )

            return _restoration_redirect(
                _restoration_url_for(
                    "document_restoration"
                )
            )

        uploaded_file = (
            _restoration_request.files.get(
                "document_image"
            )
        )

        if (
            not uploaded_file
            or not uploaded_file.filename
        ):
            _restoration_flash(
                "Сурет файлын таңдаңыз.",
                "error"
            )

            return _restoration_render_template(
                "document_restoration.html",
                restoration_csrf=restoration_csrf,
                original_url=None,
                restored_url=None,
                download_url=None
            )

        original_filename = (
            _restoration_secure_filename(
                uploaded_file.filename
            )
        )

        extension = (
            _RestorationPath(
                original_filename
            ).suffix.lower()
        )

        if extension not in _RESTORATION_EXTENSIONS:
            _restoration_flash(
                "Тек JPG, JPEG, PNG немесе TIFF "
                "суреттерін жүктеуге болады.",
                "error"
            )

            return _restoration_render_template(
                "document_restoration.html",
                restoration_csrf=restoration_csrf,
                original_url=None,
                restored_url=None,
                download_url=None
            )

        uploaded_file.seek(
            0,
            2
        )

        file_size = uploaded_file.tell()

        uploaded_file.seek(0)

        if file_size > 25 * 1024 * 1024:
            _restoration_flash(
                "Файл көлемі 25 МБ-тан аспауы керек.",
                "error"
            )

            return _restoration_render_template(
                "document_restoration.html",
                restoration_csrf=restoration_csrf,
                original_url=None,
                restored_url=None,
                download_url=None
            )

        unique_name = (
            f"{int(_restoration_time.time())}_"
            f"{_restoration_secrets.token_hex(5)}"
        )

        saved_original_name = (
            unique_name + extension
        )

        restored_filename = (
            unique_name +
            "_restored.jpg"
        )

        original_path = (
            _RESTORATION_TEMP /
            saved_original_name
        )

        restored_path = (
            _RESTORATION_OUTPUT /
            restored_filename
        )

        uploaded_file.save(original_path)

        try:
            with _RestorationImage.open(
                original_path
            ) as source_image:

                source_image.load()

                if source_image.mode not in (
                    "RGB",
                    "L"
                ):
                    processed = source_image.convert(
                        "RGB"
                    )
                else:
                    processed = source_image.copy()

            color_mode = (
                _restoration_request.form.get(
                    "color_mode",
                    "original"
                )
            )

            if color_mode == "grayscale":
                processed = (
                    _RestorationOps.grayscale(
                        processed
                    )
                )

            strength = (
                _restoration_request.form.get(
                    "strength",
                    "medium"
                )
            )

            settings = {
                "light": {
                    "contrast": 1.10,
                    "sharpness": 1.25,
                    "brightness": 1.03,
                    "median": 3
                },
                "medium": {
                    "contrast": 1.22,
                    "sharpness": 1.60,
                    "brightness": 1.06,
                    "median": 3
                },
                "strong": {
                    "contrast": 1.38,
                    "sharpness": 2.05,
                    "brightness": 1.10,
                    "median": 5
                }
            }

            chosen = settings.get(
                strength,
                settings["medium"]
            )

            if (
                _restoration_request.form.get(
                    "denoise"
                )
            ):
                processed = processed.filter(
                    _RestorationFilter.MedianFilter(
                        size=chosen["median"]
                    )
                )

            if (
                _restoration_request.form.get(
                    "auto_contrast"
                )
            ):
                processed = (
                    _RestorationOps.autocontrast(
                        processed,
                        cutoff=1
                    )
                )

                processed = (
                    _RestorationEnhance.Contrast(
                        processed
                    ).enhance(
                        chosen["contrast"]
                    )
                )

            if (
                _restoration_request.form.get(
                    "brightness"
                )
            ):
                processed = (
                    _RestorationEnhance.Brightness(
                        processed
                    ).enhance(
                        chosen["brightness"]
                    )
                )

            if (
                _restoration_request.form.get(
                    "sharpen"
                )
            ):
                processed = processed.filter(
                    _RestorationFilter.UnsharpMask(
                        radius=2,
                        percent=int(
                            90 *
                            chosen["sharpness"]
                        ),
                        threshold=3
                    )
                )

            if processed.mode != "RGB":
                processed = processed.convert(
                    "RGB"
                )

            processed.save(
                restored_path,
                format="JPEG",
                quality=94,
                optimize=True
            )

        except Exception as restoration_error:

            try:
                original_path.unlink(
                    missing_ok=True
                )
            except Exception:
                pass

            _restoration_flash(
                "Суретті өңдеу мүмкін болмады: "
                + str(restoration_error),
                "error"
            )

            return _restoration_render_template(
                "document_restoration.html",
                restoration_csrf=restoration_csrf,
                original_url=None,
                restored_url=None,
                download_url=None
            )

        original_url = _restoration_url_for(
            "static",
            filename=(
                "restoration_uploads/" +
                saved_original_name
            )
        )

        restored_url = _restoration_url_for(
            "static",
            filename=(
                "restored_documents/" +
                restored_filename
            )
        )

        download_url = _restoration_url_for(
            "download_restored_document",
            filename=restored_filename
        )

        _restoration_flash(
            "Құжаттың өңделген көшірмесі дайын.",
            "success"
        )

    return _restoration_render_template(
        "document_restoration.html",
        restoration_csrf=restoration_csrf,
        original_url=original_url,
        restored_url=restored_url,
        download_url=download_url
    )


@app.route(
    "/document-restoration/download/<path:filename>",
    endpoint="download_restored_document"
)
@_restoration_admin_required
def download_restored_document(filename):

    safe_filename = (
        _restoration_secure_filename(
            filename
        )
    )

    if (
        safe_filename != filename
        or not safe_filename.endswith(
            "_restored.jpg"
        )
    ):
        return (
            "Файл атауы жарамсыз",
            400
        )

    return _restoration_send_from_directory(
        _RESTORATION_OUTPUT,
        safe_filename,
        as_attachment=True,
        download_name=safe_filename
    )

# === END DOCUMENT RESTORATION FEATURE V1 ===





# === HANDWRITING RECOGNITION FEATURE V1 ===
# V2: Arabic verification, rotation and confidence

from pathlib import Path as _HwPath
from functools import wraps as _hw_wraps

from flask import (
    request as _hw_request,
    render_template as _hw_render_template,
    redirect as _hw_redirect,
    url_for as _hw_url_for,
    session as _hw_session,
    flash as _hw_flash,
    send_from_directory as _hw_send_from_directory
)

from werkzeug.utils import (
    secure_filename as _hw_secure_filename
)

from PIL import (
    Image as _HwImage,
    ImageOps as _HwImageOps,
    ImageFilter as _HwImageFilter,
    ImageEnhance as _HwImageEnhance
)

import pytesseract as _hw_tesseract
from pytesseract import Output as _HwOutput

import secrets as _hw_secrets
import time as _hw_time
import statistics as _hw_statistics


_HW_ROOT = _HwPath(app.root_path)

_HW_DIRECTORY = (
    _HW_ROOT /
    "static" /
    "handwriting"
)

_HW_DIRECTORY.mkdir(
    parents=True,
    exist_ok=True
)

_HW_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".tif",
    ".tiff"
}


def _hw_admin_required(function):

    @_hw_wraps(function)
    def protected(*args, **kwargs):

        if not (
            _hw_session.get("admin_logged_in")
            or
            _hw_session.get("is_admin")
        ):
            _hw_flash(
                "Алдымен әкімші жүйесіне кіріңіз.",
                "error"
            )

            login_endpoint = (
                "admin_login_v4"
                if "admin_login_v4"
                in app.view_functions
                else "admin_login"
            )

            return _hw_redirect(
                _hw_url_for(login_endpoint)
            )

        return function(*args, **kwargs)

    return protected


def _hw_csrf_token():

    token = _hw_session.get(
        "_handwriting_csrf"
    )

    if not token:
        token = _hw_secrets.token_hex(24)

        _hw_session[
            "_handwriting_csrf"
        ] = token

    return token


def _hw_preprocess(image):

    processed = _HwImageOps.grayscale(
        image
    )

    width, height = processed.size

    # Colab-та жылдам өңдеу үшін сурет ең көбі 2 есе үлкейеді.
    if width < 1200:
        scale = 2

        processed = processed.resize(
            (
                width * scale,
                height * scale
            ),
            _HwImage.Resampling.LANCZOS
        )

    # Өте үлкен суретті OCR алдында кішірейту
    max_dimension = 1400

    if max(processed.size) > max_dimension:
        processed.thumbnail(
            (
                max_dimension,
                max_dimension
            ),
            _HwImage.Resampling.LANCZOS
        )

    processed = _HwImageOps.autocontrast(
        processed,
        cutoff=1
    )

    processed = (
        _HwImageEnhance.Contrast(
            processed
        ).enhance(1.35)
    )

    processed = processed.filter(
        _HwImageFilter.MedianFilter(
            size=3
        )
    )

    processed = processed.filter(
        _HwImageFilter.UnsharpMask(
            radius=2,
            percent=145,
            threshold=3
        )
    )

    return processed


def _hw_read_image(image, language):

    # OCR тек бір рет орындалады.
    data = _hw_tesseract.image_to_data(
        image,
        lang=language,
        config="--oem 3 --psm 11",
        output_type=_HwOutput.DICT,
        timeout=90
    )

    confidences = []
    lines = {}
    word_count = 0

    total_items = len(
        data.get("text", [])
    )

    for index in range(total_items):

        word = str(
            data["text"][index] or ""
        ).strip()

        if not word:
            continue

        word_count += 1

        try:
            confidence = float(
                data["conf"][index]
            )
        except Exception:
            confidence = -1

        if confidence >= 0:
            confidences.append(
                confidence
            )

        line_key = (
            data.get("block_num", [0] * total_items)[index],
            data.get("par_num", [0] * total_items)[index],
            data.get("line_num", [0] * total_items)[index]
        )

        if line_key not in lines:
            lines[line_key] = []

        lines[line_key].append(word)

    recognized_lines = []

    for line_words in lines.values():
        line_text = " ".join(line_words).strip()

        if line_text:
            recognized_lines.append(
                line_text
            )

    recognized_text = chr(10).join(
        recognized_lines
    ).strip()

    confidence = (
        round(
            _hw_statistics.mean(
                confidences
            ),
            1
        )
        if confidences
        else 0.0
    )

    return {
        "text": recognized_text,
        "confidence": confidence,
        "word_count": word_count
    }


@app.route(
    "/handwriting-recognition",
    methods=["GET", "POST"],
    endpoint="handwriting_recognition"
)
@_hw_admin_required
def handwriting_recognition():

    csrf_token = _hw_csrf_token()

    context = {
        "handwriting_csrf": csrf_token,
        "image_url": None,
        "recognized_text": "",
        "download_url": None,
        "ocr_language_used": None,
        "ocr_confidence": None,
        "rotation_used": None,
        "ocr_warning": None
    }

    if _hw_request.method == "GET":
        return _hw_render_template(
            "handwriting_recognition.html",
            **context
        )

    submitted_token = (
        _hw_request.form.get(
            "handwriting_csrf",
            ""
        )
    )

    if not _hw_secrets.compare_digest(
        submitted_token,
        csrf_token
    ):
        _hw_flash(
            "Қауіпсіздік таңбасы жарамсыз.",
            "error"
        )

        return _hw_redirect(
            _hw_url_for(
                "handwriting_recognition"
            )
        )

    uploaded_file = (
        _hw_request.files.get(
            "handwriting_image"
        )
    )

    if (
        not uploaded_file
        or not uploaded_file.filename
    ):
        _hw_flash(
            "Сурет файлын таңдаңыз.",
            "error"
        )

        return _hw_render_template(
            "handwriting_recognition.html",
            **context
        )

    original_name = (
        _hw_secure_filename(
            uploaded_file.filename
        )
    )

    extension = (
        _HwPath(
            original_name
        ).suffix.lower()
    )

    if extension not in _HW_EXTENSIONS:
        _hw_flash(
            "Файл пішімі жарамсыз.",
            "error"
        )

        return _hw_render_template(
            "handwriting_recognition.html",
            **context
        )

    requested_language = (
        _hw_request.form.get(
            "language",
            "ara"
        )
    )

    available_languages = set(
        _hw_tesseract.get_languages(
            config=""
        )
    )

    requested_parts = (
        requested_language.split("+")
    )

    missing_languages = [
        language
        for language in requested_parts
        if language not in available_languages
    ]

    if missing_languages:
        _hw_flash(
            "OCR тіл моделі табылмады: "
            + ", ".join(missing_languages),
            "error"
        )

        return _hw_render_template(
            "handwriting_recognition.html",
            **context
        )

    unique_id = (
        str(int(_hw_time.time()))
        + "_"
        + _hw_secrets.token_hex(5)
    )

    source_name = (
        unique_id + extension
    )

    processed_name = (
        unique_id + "_best.png"
    )

    text_name = (
        unique_id + "_recognized.txt"
    )

    source_path = (
        _HW_DIRECTORY /
        source_name
    )

    processed_path = (
        _HW_DIRECTORY /
        processed_name
    )

    text_path = (
        _HW_DIRECTORY /
        text_name
    )

    uploaded_file.save(source_path)

    try:
        with _HwImage.open(
            source_path
        ) as opened_image:

            opened_image.load()

            if opened_image.mode != "RGB":
                original_image = (
                    opened_image.convert("RGB")
                )
            else:
                original_image = (
                    opened_image.copy()
                )

        rotation_results = []

        # Жүктелген суретті бір бағытта ғана танимыз.
        # Бұл Colab-тағы ұзақ күтуді азайтады.
        for angle in [0]:

            rotated_image = (
                original_image.rotate(
                    angle,
                    expand=True,
                    fillcolor="white"
                )
            )

            processed_image = (
                _hw_preprocess(
                    rotated_image
                )
            )

            ocr_result = _hw_read_image(
                processed_image,
                requested_language
            )

            rotation_results.append({
                "angle": angle,
                "image": processed_image,
                "text": ocr_result["text"],
                "confidence": (
                    ocr_result["confidence"]
                ),
                "word_count": (
                    ocr_result["word_count"]
                )
            })

        best_result = max(
            rotation_results,
            key=lambda item: (
                item["confidence"],
                item["word_count"]
            )
        )

        best_result["image"].save(
            processed_path,
            format="PNG",
            optimize=True
        )

        recognized_text = (
            best_result["text"].strip()
        )

        confidence = float(
            best_result["confidence"]
        )

        warning = None

        if confidence < 25:
            warning = (
                "Тану сенімділігі өте төмен. "
                "Бұл нәтиже тарихи мәтін ретінде "
                "пайдалануға жарамайды. Қолжазбаны "
                "маман тексеруі қажет."
            )

        elif confidence < 45:
            warning = (
                "Тану сенімділігі төмен. "
                "Мәтіндегі әр сөзді түпнұсқамен "
                "салыстырып тексеріңіз."
            )

        elif confidence < 65:
            warning = (
                "Мәтін жартылай танылды. "
                "Қате әріптер болуы мүмкін."
            )

        if not recognized_text:
            recognized_text = (
                "Мәтін автоматты түрде танылмады."
            )

            warning = (
                "Қолжазба автоматты тануға жарамсыз. "
                "Палеографиялық сараптама қажет."
            )

        report_text = chr(10).join([
            "OCR тілі: " + str(requested_language),
            "Сенімділік: " + str(confidence) + "%",
            "Бұрылу: " + str(best_result["angle"]) + "°",
            "",
            recognized_text
        ])

        text_path.write_text(
            report_text,
            encoding="utf-8"
        )

        context.update({
            "image_url": _hw_url_for(
                "static",
                filename=(
                    "handwriting/"
                    + processed_name
                )
            ),
            "recognized_text": recognized_text,
            "download_url": _hw_url_for(
                "download_handwriting_text",
                filename=text_name
            ),
            "ocr_language_used": (
                requested_language
            ),
            "ocr_confidence": confidence,
            "rotation_used": (
                best_result["angle"]
            ),
            "ocr_warning": warning
        })

        _hw_flash(
            "Қолжазбаны тексеру аяқталды.",
            "success"
        )

    except Exception as error:

        _hw_flash(
            "OCR қатесі: " + str(error),
            "error"
        )

    return _hw_render_template(
        "handwriting_recognition.html",
        **context
    )


@app.route(
    "/handwriting-recognition/download/<path:filename>",
    endpoint="download_handwriting_text"
)
@_hw_admin_required
def download_handwriting_text(filename):

    safe_filename = (
        _hw_secure_filename(filename)
    )

    if (
        safe_filename != filename
        or not safe_filename.endswith(
            "_recognized.txt"
        )
    ):
        return "Файл атауы жарамсыз", 400

    return _hw_send_from_directory(
        _HW_DIRECTORY,
        safe_filename,
        as_attachment=True,
        download_name=safe_filename
    )

# === END HANDWRITING RECOGNITION FEATURE V1 ===





# === ARCHIVE ANALYTICS FEATURE V1 ===

from pathlib import Path as _AnalyticsPath
from functools import wraps as _analytics_wraps
from types import SimpleNamespace as _AnalyticsNamespace

from flask import (
    render_template as _analytics_render_template,
    session as _analytics_session,
    redirect as _analytics_redirect,
    url_for as _analytics_url_for,
    flash as _analytics_flash
)

import sqlite3 as _analytics_sqlite3


_ANALYTICS_ROOT = _AnalyticsPath(
    app.root_path
)

_ANALYTICS_DATABASE = (
    _ANALYTICS_ROOT /
    "database" /
    "syrmura.db"
)


def _analytics_admin_required(function):

    @_analytics_wraps(function)
    def protected(*args, **kwargs):

        logged_in = (
            _analytics_session.get(
                "admin_logged_in"
            )
            or
            _analytics_session.get(
                "is_admin"
            )
        )

        if not logged_in:
            _analytics_flash(
                "Алдымен әкімші жүйесіне кіріңіз.",
                "error"
            )

            login_endpoint = (
                "admin_login_v4"
                if "admin_login_v4"
                in app.view_functions
                else "admin_login"
            )

            return _analytics_redirect(
                _analytics_url_for(
                    login_endpoint
                )
            )

        return function(*args, **kwargs)

    return protected


def _analytics_size(size_value):

    size_value = int(
        size_value or 0
    )

    if size_value < 1024:
        return str(size_value) + " Б"

    if size_value < 1024 * 1024:
        return (
            str(
                round(
                    size_value / 1024,
                    1
                )
            )
            + " КБ"
        )

    if size_value < 1024 * 1024 * 1024:
        return (
            str(
                round(
                    size_value /
                    (1024 * 1024),
                    1
                )
            )
            + " МБ"
        )

    return (
        str(
            round(
                size_value /
                (1024 * 1024 * 1024),
                2
            )
        )
        + " ГБ"
    )


@app.route(
    "/archive-analytics",
    endpoint="archive_analytics"
)
@_analytics_admin_required
def archive_analytics():

    connection = _analytics_sqlite3.connect(
        _ANALYTICS_DATABASE
    )

    connection.row_factory = (
        _analytics_sqlite3.Row
    )

    try:
        total = connection.execute(
            "SELECT COUNT(*) FROM documents"
        ).fetchone()[0]

        status_rows = connection.execute(
            """
            SELECT
                COALESCE(status, 'pending') AS status,
                COUNT(*) AS amount
            FROM documents
            GROUP BY COALESCE(status, 'pending')
            """
        ).fetchall()

        status_counts = {
            row["status"]: row["amount"]
            for row in status_rows
        }

        subsection_rows = connection.execute(
            """
            SELECT
                COALESCE(
                    NULLIF(TRIM(subsection), ''),
                    'Бөлімше көрсетілмеген'
                ) AS name,
                COUNT(*) AS amount
            FROM documents
            GROUP BY name
            ORDER BY amount DESC, name
            """
        ).fetchall()

        maximum_subsection = max(
            [
                row["amount"]
                for row in subsection_rows
            ],
            default=1
        )

        subsection_stats = [
            {
                "name": row["name"],
                "count": row["amount"],
                "percent": round(
                    row["amount"]
                    / maximum_subsection
                    * 100,
                    1
                )
            }
            for row in subsection_rows
        ]

        year_rows = connection.execute(
            """
            SELECT
                CAST(document_year AS TEXT) AS name,
                COUNT(*) AS amount
            FROM documents
            WHERE document_year IS NOT NULL
              AND document_year != ''
            GROUP BY document_year
            ORDER BY document_year DESC
            LIMIT 15
            """
        ).fetchall()

        maximum_year = max(
            [
                row["amount"]
                for row in year_rows
            ],
            default=1
        )

        year_stats = [
            {
                "name": row["name"],
                "count": row["amount"],
                "percent": round(
                    row["amount"]
                    / maximum_year
                    * 100,
                    1
                )
            }
            for row in year_rows
        ]

        size_row = connection.execute(
            """
            SELECT
                COALESCE(SUM(file_size), 0),
                COALESCE(AVG(file_size), 0)
            FROM documents
            """
        ).fetchone()

        location_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM documents
            WHERE latitude IS NOT NULL
              AND longitude IS NOT NULL
            """
        ).fetchone()[0]

        source_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM documents
            WHERE source_url IS NOT NULL
              AND TRIM(source_url) != ''
            """
        ).fetchone()[0]

        recent_rows = connection.execute(
            """
            SELECT
                title,
                COALESCE(status, 'pending') AS status
            FROM documents
            ORDER BY id DESC
            LIMIT 8
            """
        ).fetchall()

        recent_documents = [
            _AnalyticsNamespace(
                title=(
                    row["title"]
                    or "Атауы көрсетілмеген"
                ),
                status=row["status"]
            )
            for row in recent_rows
        ]

    finally:
        connection.close()

    totals = _AnalyticsNamespace(
        total=total,
        published=status_counts.get(
            "published",
            0
        ),
        pending=status_counts.get(
            "pending",
            0
        ),
        returned=status_counts.get(
            "returned",
            0
        )
    )

    return _analytics_render_template(
        "archive_analytics.html",
        totals=totals,
        subsection_stats=subsection_stats,
        year_stats=year_stats,
        total_size=_analytics_size(
            size_row[0]
        ),
        average_size=_analytics_size(
            size_row[1]
        ),
        location_count=location_count,
        source_count=source_count,
        recent_documents=recent_documents
    )

# === END ARCHIVE ANALYTICS FEATURE V1 ===





# === DIGITIZATION ADMIN ACCESS V1 ===

from flask import (
    request as _digitization_request,
    session as _digitization_session,
    redirect as _digitization_redirect
)


@app.before_request
def protect_digitization_page():

    protected_paths = {
        "/digitization"
    }

    if (
        _digitization_request.path
        not in protected_paths
    ):
        return None

    admin_logged_in = (
        _digitization_session.get(
            "admin_logged_in"
        )
        or
        _digitization_session.get(
            "is_admin"
        )
    )

    if not admin_logged_in:
        return _digitization_redirect(
            "/admin/login?next=/digitization"
        )

    return None

# === END DIGITIZATION ADMIN ACCESS V1 ===











# === RESTORATION ADMIN PROTECTION START ===
@app.before_request
def protect_document_restoration_for_admin():
    from flask import request, session, redirect, url_for

    if request.path == '/document-restoration':
        admin_access = (
            session.get("admin_logged_in")
            or session.get("is_admin")
        )

        if not admin_access:
            return redirect(
                url_for("admin_login_v4")
            )
# === RESTORATION ADMIN PROTECTION END ===



# === OCR QUALITY ADMIN PROTECTION START ===
@app.before_request
def protect_ocr_and_quality_for_admin():
    from flask import request, session, redirect, url_for

    protected_paths = {
        "/ocr",
        "/quality-check"
    }

    if request.path in protected_paths:
        admin_access = (
            session.get("admin_logged_in")
            or session.get("is_admin")
        )

        if not admin_access:
            return redirect(
                url_for("admin_login_v4")
            )
# === OCR QUALITY ADMIN PROTECTION END ===







# === SMART SEARCH ROUTE START ===
@app.route("/smart-search", methods=["GET"])
def public_smart_search():
    import sqlite3
    from pathlib import Path
    from flask import request, render_template

    query = request.args.get(
        "q",
        ""
    ).strip()

    documents = []

    database_path = (
        Path(__file__).resolve().parent
        / "database"
        / "syrmura.db"
    )

    if query and database_path.exists():
        connection = sqlite3.connect(
            str(database_path)
        )

        connection.row_factory = sqlite3.Row

        search_value = f"%{query}%"

        documents = connection.execute(
            """
            SELECT *
            FROM documents
            WHERE status = 'published'
              AND (
                    COALESCE(title, '') LIKE ?
                 OR CAST(
                        COALESCE(document_year, '')
                        AS TEXT
                    ) LIKE ?
                 OR COALESCE(section, '') LIKE ?
                 OR COALESCE(subsection, '') LIKE ?
                 OR COALESCE(description, '') LIKE ?
                 OR COALESCE(source_name, '') LIKE ?
                 OR COALESCE(location_name, '') LIKE ?
              )
            ORDER BY
                document_year DESC,
                created_at DESC,
                id DESC
            LIMIT 100
            """,
            (
                search_value,
                search_value,
                search_value,
                search_value,
                search_value,
                search_value,
                search_value
            )
        ).fetchall()

        connection.close()

    return render_template(
        "smart_search.html",
        query=query,
        documents=documents
    )
# === SMART SEARCH ROUTE END ===



# === AI LAB PUBLIC ROUTE START ===
@app.route("/ai-lab", methods=["GET"])
def public_ai_lab():
    import sqlite3
    import json
    from pathlib import Path
    from flask import render_template

    database_path = (
        Path(__file__).resolve().parent
        / "database"
        / "syrmura.db"
    )

    documents = []

    if database_path.exists():
        connection = sqlite3.connect(
            str(database_path)
        )

        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT
                id,
                title,
                document_year,
                section,
                subsection,
                description,
                source_name,
                source_url,
                location_name,
                latitude,
                longitude
            FROM documents
            WHERE status = 'published'
            ORDER BY
                document_year ASC,
                created_at ASC,
                id ASC
            """
        ).fetchall()

        documents = [
            dict(row)
            for row in rows
        ]

        connection.close()

    return render_template(
        "ai_lab.html",
        documents_json=json.dumps(
            documents,
            ensure_ascii=False,
            default=str
        )
    )
# === AI LAB PUBLIC ROUTE END ===



# === SYRMURA ROLE AUTH START ===

def syrmura_auth_database():
    from pathlib import Path

    return (
        Path(__file__).resolve().parent
        / "database"
        / "syrmura.db"
    )


def get_auth_csrf():
    from flask import session
    import secrets

    token = session.get("_public_auth_csrf")

    if not token:
        token = secrets.token_urlsafe(32)
        session["_public_auth_csrf"] = token

    return token


def validate_auth_csrf(value):
    from flask import session
    import secrets

    expected = session.get("_public_auth_csrf", "")

    return bool(
        value
        and expected
        and secrets.compare_digest(value, expected)
    )


@app.route("/welcome", methods=["GET"])
def public_welcome():
    from flask import session, redirect, url_for, render_template

    if (
        session.get("user_logged_in")
        or session.get("admin_logged_in")
    ):
        if (
            session.get("user_role") == "admin"
            or session.get("is_admin")
        ):
            return redirect(url_for("select_user_mode"))

        return redirect(url_for("home_v4"))

    return render_template("welcome.html")


@app.route("/register", methods=["GET", "POST"])
def user_register():
    import sqlite3
    import re
    from datetime import datetime
    from flask import (
        request,
        render_template,
        redirect,
        url_for,
        flash
    )
    from werkzeug.security import generate_password_hash

    if request.method == "POST":
        csrf_value = request.form.get("csrf_token", "")

        if not validate_auth_csrf(csrf_value):
            flash(
                "Қауіпсіздік белгісі жарамсыз. "
                "Бетті жаңартып қайталап көріңіз.",
                "error"
            )

            return redirect(url_for("user_register"))

        full_name = request.form.get(
            "full_name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        password_confirm = request.form.get(
            "password_confirm",
            ""
        )

        if len(full_name) < 2:
            flash("Аты-жөніңізді дұрыс енгізіңіз.", "error")

        elif not re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            email
        ):
            flash(
                "Электрондық пошта дұрыс емес.",
                "error"
            )

        elif len(password) < 8:
            flash(
                "Құпиясөз кемінде 8 таңбадан тұруы керек.",
                "error"
            )

        elif password != password_confirm:
            flash(
                "Құпиясөздер бірдей емес.",
                "error"
            )

        else:
            connection = sqlite3.connect(
                str(syrmura_auth_database())
            )

            existing_user = connection.execute(
                """
                SELECT id
                FROM users
                WHERE LOWER(username) = ?
                   OR LOWER(COALESCE(email, '')) = ?
                LIMIT 1
                """,
                (email, email)
            ).fetchone()

            if existing_user:
                connection.close()

                flash(
                    "Бұл электрондық пошта бұрын тіркелген.",
                    "error"
                )

            else:
                connection.execute(
                    """
                    INSERT INTO users (
                        username,
                        email,
                        full_name,
                        password_hash,
                        role,
                        is_active,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, 'user', 1, ?)
                    """,
                    (
                        email,
                        email,
                        full_name,
                        generate_password_hash(password),
                        datetime.now().isoformat(
                            timespec="seconds"
                        )
                    )
                )

                connection.commit()
                connection.close()

                flash(
                    "Тіркелу сәтті аяқталды. "
                    "Енді жүйеге кіріңіз.",
                    "success"
                )

                return redirect(url_for("user_login"))

    return render_template(
        "user_register.html",
        auth_csrf=get_auth_csrf()
    )


@app.route("/login", methods=["GET", "POST"])
def user_login():
    import sqlite3
    from flask import (
        request,
        render_template,
        redirect,
        url_for,
        flash,
        session
    )
    from werkzeug.security import check_password_hash

    next_url = request.args.get(
        "next",
        request.form.get("next", "")
    )

    if request.method == "POST":
        csrf_value = request.form.get("csrf_token", "")

        if not validate_auth_csrf(csrf_value):
            flash(
                "Қауіпсіздік белгісі жарамсыз. "
                "Бетті жаңартып қайталап көріңіз.",
                "error"
            )

            return redirect(url_for("user_login"))

        login_value = request.form.get(
            "login",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        connection = sqlite3.connect(
            str(syrmura_auth_database())
        )

        connection.row_factory = sqlite3.Row

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE (
                    LOWER(username) = ?
                 OR LOWER(COALESCE(email, '')) = ?
            )
              AND COALESCE(is_active, 1) = 1
            LIMIT 1
            """,
            (login_value, login_value)
        ).fetchone()

        connection.close()

        password_valid = False

        if user and user["password_hash"]:
            try:
                password_valid = check_password_hash(
                    user["password_hash"],
                    password
                )
            except (ValueError, TypeError):
                password_valid = False

        if not user or not password_valid:
            flash(
                "Логин немесе құпиясөз дұрыс емес.",
                "error"
            )

        else:
            session.clear()

            role = (
                user["role"]
                if user["role"]
                else "user"
            ).lower()

            session["user_logged_in"] = True
            session["user_id"] = user["id"]
            session["user_username"] = user["username"]
            session["user_email"] = (
                user["email"]
                if "email" in user.keys()
                else user["username"]
            )
            session["user_full_name"] = (
                user["full_name"]
                if "full_name" in user.keys()
                else user["username"]
            )
            session["user_role"] = role

            if role == "admin":
                session["admin_logged_in"] = True
                session["is_admin"] = True
                session["admin_username"] = user["username"]
                session["admin_email"] = (
                    user["email"]
                    if "email" in user.keys()
                    else user["username"]
                )

                return redirect(
                    url_for("select_user_mode")
                )

            # Қауіпсіз ішкі next сілтемесі ғана қабылданады
            if (
                next_url
                and next_url.startswith("/")
                and not next_url.startswith("//")
                and not next_url.startswith("/admin")
            ):
                return redirect(next_url)

            return redirect(url_for("home_v4"))

    return render_template(
        "user_login.html",
        auth_csrf=get_auth_csrf(),
        next_url=next_url
    )


@app.route("/mode-select", methods=["GET"])
def select_user_mode():
    from flask import session, redirect, url_for, render_template

    is_admin_user = (
        session.get("user_role") == "admin"
        or session.get("is_admin")
        or session.get("admin_logged_in")
    )

    if not is_admin_user:
        return redirect(url_for("home_v4"))

    return render_template("mode_select.html")


@app.route("/logout", methods=["GET"])
def user_logout():
    from flask import session, redirect, url_for

    session.clear()

    return redirect(url_for("public_welcome"))


@app.before_request
def syrmura_role_access_control():
    from flask import request, session, redirect, url_for

    path = request.path

    # Кіруге рұқсат берілетін ашық беттер
    public_paths = {
        "/welcome",
        "/login",
        "/register"
    }

    if path in public_paths:
        return None

    if path.startswith("/static/"):
        return None

    # Ескі әкімші кіру беті ашық қалады
    if path == "/admin/login":
        return None

    user_authenticated = bool(
        session.get("user_logged_in")
        or session.get("admin_logged_in")
    )

    is_admin_user = bool(
        session.get("user_role") == "admin"
        or session.get("is_admin")
        or session.get("admin_logged_in")
    )

    # Әкімші беттерінің қорғанысы
    if path.startswith("/admin"):
        if not is_admin_user:
            if user_authenticated:
                return redirect(url_for("home_v4"))

            return redirect(
                url_for(
                    "user_login",
                    next=path
                )
            )

        return None

    # Қалған платформаны тек кірген адам пайдаланады
    if not user_authenticated:
        return redirect(url_for("public_welcome"))

    return None

# === SYRMURA ROLE AUTH END ===


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5014,
        debug=False,
        use_reloader=False
    )
