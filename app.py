from __future__ import annotations

import json
import hashlib
import hmac
import math
import os
import random
import secrets
import sqlite3
import csv
import io
from threading import Lock
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("DATA_DIR", str(BASE_DIR / "data")))
DB_PATH = Path(os.getenv("DATABASE_PATH", str(DATA_DIR / "naryadai.db")))
APP_ENV = os.getenv("APP_ENV", "development").lower()
SESSION_COOKIE_NAME = "naryadai_session"
SESSION_TTL_SECONDS = 12 * 60 * 60
SESSION_COOKIE_SECURE = APP_ENV == "production"
PIN_HASH_ITERATIONS = 210_000
LOGIN_FAILURE_LIMIT = 5
LOGIN_LOCKOUT_SECONDS = 10 * 60
MIN_TRAINING_DURATION_SECONDS = 60
login_attempts: dict[str, tuple[int, datetime | None]] = {}
login_attempts_lock = Lock()

DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="НарядAI", version="0.1.0")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections = [ws for ws in self.active_connections if ws != websocket]

    async def broadcast(self, message: dict[str, Any]) -> None:
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)


manager = ConnectionManager()


class LoginRequest(BaseModel):
    username: str
    pin: str = Field(min_length=4, max_length=128)


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_.-]+$")
    full_name: str = Field(min_length=2, max_length=120)
    pin: str = Field(min_length=8, max_length=128)
    role_code: str
    team: str = Field(default="", max_length=80)


class ResourceCreateRequest(BaseModel):
    resource_type: str
    code: str = Field(min_length=2, max_length=32, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
    title: str = Field(min_length=2, max_length=120)
    unit: str = Field(min_length=1, max_length=24)


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def precise_now_iso() -> str:
    return datetime.now().isoformat(sep=" ", timespec="microseconds")


def hash_pin(pin: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, PIN_HASH_ITERATIONS)
    return f"pbkdf2_sha256${salt.hex()}${digest.hex()}"


def verify_pin(stored_pin: str, submitted_pin: str) -> bool:
    if stored_pin.startswith("pbkdf2_sha256$"):
        try:
            _, salt_hex, digest_hex = stored_pin.split("$", 2)
            digest = hashlib.pbkdf2_hmac("sha256", submitted_pin.encode("utf-8"), bytes.fromhex(salt_hex), PIN_HASH_ITERATIONS)
            return hmac.compare_digest(digest.hex(), digest_hex)
        except ValueError:
            return False
    return hmac.compare_digest(stored_pin, submitted_pin)


def session_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def normalize_resource_items(value: Any, field_name: str, resource_type: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise HTTPException(status_code=422, detail=f"Поле {field_name} должно содержать список ресурсов")
    if resource_type not in {"material", "tool"}:
        raise HTTPException(status_code=422, detail="Неизвестный тип ресурса")

    normalized: list[dict[str, Any]] = []
    conn = get_connection()
    table_name = "materials" if resource_type == "material" else "tools"
    try:
        for item in value:
            if not isinstance(item, dict):
                raise HTTPException(status_code=422, detail=f"Некорректная позиция в поле {field_name}")
            code = str(item.get("code") or "").strip().upper()
            quantity = item.get("quantity")
            if not code:
                raise HTTPException(status_code=422, detail=f"Выберите ресурс из каталога: {field_name}")
            if isinstance(quantity, bool) or not isinstance(quantity, (int, float)):
                raise HTTPException(status_code=422, detail=f"Количество для {field_name} должно быть числом")
            quantity_value = float(quantity)
            if not math.isfinite(quantity_value) or not 0 < quantity_value <= 1_000_000:
                raise HTTPException(status_code=422, detail=f"Количество для {field_name} должно быть больше нуля")
            catalog_item = conn.execute(
                f"SELECT title, unit FROM {table_name} WHERE code = ?",
                (code,),
            ).fetchone()
            if not catalog_item:
                raise HTTPException(status_code=422, detail=f"Ресурс {code} отсутствует в каталоге")
            normalized.append({
                "code": code,
                "name": catalog_item["title"],
                "quantity": quantity_value,
                "unit": catalog_item["unit"],
            })
    finally:
        conn.close()
    return normalized


def encode_resource_items(items: list[dict[str, Any]]) -> str:
    return json.dumps(items, ensure_ascii=False, separators=(",", ":"))


def save_resource_items(
    conn: sqlite3.Connection,
    work_order_id: int,
    phase: str,
    resource_type: str,
    items: list[dict[str, Any]],
) -> None:
    conn.executemany(
        "INSERT INTO work_order_resource_items (work_order_id, phase, resource_type, resource_code, name, quantity, unit) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            (work_order_id, phase, resource_type, item["code"], item["name"], item["quantity"], item["unit"])
            for item in items
        ],
    )


def login_is_locked(key: str) -> bool:
    now = datetime.now()
    with login_attempts_lock:
        failures, locked_until = login_attempts.get(key, (0, None))
        if locked_until and locked_until <= now:
            login_attempts.pop(key, None)
            return False
        return bool(locked_until and locked_until > now)


def record_failed_login(key: str) -> None:
    now = datetime.now()
    with login_attempts_lock:
        failures, locked_until = login_attempts.get(key, (0, None))
        if locked_until and locked_until > now:
            return
        failures += 1
        if failures >= LOGIN_FAILURE_LIMIT:
            locked_until = now + timedelta(seconds=LOGIN_LOCKOUT_SECONDS)
        login_attempts[key] = (failures, locked_until)


def clear_login_failures(key: str) -> None:
    with login_attempts_lock:
        login_attempts.pop(key, None)


def get_session_user(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None

    conn = get_connection()
    row = conn.execute(
        """
        SELECT u.id, u.username, u.full_name, u.role_code, r.title AS role_title, u.team, u.status
        FROM user_sessions s
        JOIN users u ON u.id = s.user_id
        LEFT JOIN roles r ON r.code = u.role_code
        WHERE s.token_hash = ? AND s.expires_at > ? AND u.is_active = 1
        """,
        (session_token_hash(token), now_iso()),
    ).fetchone()
    conn.close()
    if not row:
        return None

    return {
        "id": row["id"],
        "username": row["username"],
        "full_name": row["full_name"],
        "role": row["role_code"],
        "role_title": row["role_title"],
        "team": row["team"],
        "status": row["status"],
    }


def create_session(conn: sqlite3.Connection, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    created_at = datetime.now()
    expires_at = created_at + timedelta(seconds=SESSION_TTL_SECONDS)
    conn.execute("DELETE FROM user_sessions WHERE expires_at <= ?", (now_iso(),))
    conn.execute(
        "INSERT INTO user_sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (
            session_token_hash(token),
            user_id,
            created_at.strftime("%Y-%m-%d %H:%M:%S"),
            expires_at.strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    return token


@app.middleware("http")
async def require_api_session(request: Request, call_next: Any) -> Response:
    path = request.url.path
    if not path.startswith("/api/") or path in {"/api/health", "/api/login"}:
        return await call_next(request)

    user = get_session_user(request.cookies.get(SESSION_COOKIE_NAME))
    if not user:
        return JSONResponse(status_code=401, content={"detail": "Требуется войти в систему"})

    request.state.user = user
    manager_only = (
        path.startswith("/api/ai/")
        or path.startswith("/api/reports/")
        or path.startswith("/api/training/")
        or path in {"/api/summary", "/api/test-data", "/api/history-summary"}
    )
    if path == "/api/users" and user["role"] != "admin":
        return JSONResponse(status_code=403, content={"detail": "Управлять пользователями может только администратор"})
    if path == "/api/resources" and request.method == "POST" and user["role"] != "admin":
        return JSONResponse(status_code=403, content={"detail": "Изменять каталог ресурсов может только администратор"})
    if manager_only and user["role"] not in {"master", "chief", "admin"}:
        return JSONResponse(status_code=403, content={"detail": "Недостаточно прав"})
    return await call_next(request)


def ensure_columns() -> None:
    conn = get_connection()
    tables = [
        ("work_orders", [
            ("priority", "TEXT"),
            ("executor_user", "TEXT"),
            ("site_code", "TEXT"),
            ("equipment_code", "TEXT"),
            ("title", "TEXT"),
            ("description", "TEXT"),
            ("comment", "TEXT"),
            ("reason", "TEXT"),
            ("photo_before", "TEXT"),
            ("photo_after", "TEXT"),
            ("issue_code", "TEXT"),
            ("materials", "TEXT"),
            ("planned_crew_size", "INTEGER"),
            ("planned_materials", "TEXT"),
            ("planned_tools", "TEXT"),
            ("actual_crew_size", "INTEGER"),
            ("tools_used", "TEXT"),
            ("last_comment", "TEXT"),
            ("updated_at", "TEXT"),
            ("accepted_at", "TEXT"),
            ("started_at", "TEXT"),
            ("completed_at", "TEXT"),
            ("closed_at", "TEXT"),
            ("ai_verdict", "TEXT"),
            ("ai_score", "INTEGER"),
        ]),
    ]
    for table_name, columns in tables:
        existing = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        existing_names = {row[1] for row in existing}
        for col_name, col_type in columns:
            if col_name not in existing_names:
                conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS work_order_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            work_order_id INTEGER NOT NULL,
            event TEXT NOT NULL,
            user TEXT,
            reason TEXT,
            details TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT NOT NULL UNIQUE,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS work_order_resource_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            work_order_id INTEGER NOT NULL,
            phase TEXT NOT NULL CHECK (phase IN ('planned', 'actual')),
            resource_type TEXT NOT NULL CHECK (resource_type IN ('material', 'tool')),
            resource_code TEXT NOT NULL,
            name TEXT NOT NULL,
            quantity REAL NOT NULL CHECK (quantity > 0),
            unit TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (work_order_id) REFERENCES work_orders(id)
        )
        """
    )
    tool_columns = {row[1] for row in conn.execute("PRAGMA table_info(tools)").fetchall()}
    if not tool_columns:
        conn.execute(
            "CREATE TABLE tools (id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE NOT NULL, title TEXT NOT NULL, unit TEXT NOT NULL)"
        )
    resource_columns = {row[1] for row in conn.execute("PRAGMA table_info(work_order_resource_items)").fetchall()}
    if "resource_code" not in resource_columns:
        conn.execute("ALTER TABLE work_order_resource_items ADD COLUMN resource_code TEXT")
    conn.commit()
    conn.close()


def init_db() -> None:
    conn = get_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            pin TEXT NOT NULL,
            role_code TEXT NOT NULL,
            team TEXT,
            status TEXT DEFAULT 'free',
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (role_code) REFERENCES roles(code)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS equipment (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site_code TEXT NOT NULL,
            code TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            type_group TEXT NOT NULL,
            status TEXT DEFAULT 'ok'
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS issue_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            group_code TEXT NOT NULL,
            title TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS materials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            unit TEXT NOT NULL,
            standard_consumption REAL DEFAULT 1
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS tools (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            unit TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS work_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            number INTEGER NOT NULL,
            site_code TEXT NOT NULL,
            equipment_code TEXT NOT NULL,
            priority TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'issued',
            executor_user TEXT,
            title TEXT NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL,
            due_at TEXT,
            type TEXT DEFAULT 'planned',
            comment TEXT,
            reason TEXT,
            photo_before TEXT,
            photo_after TEXT,
            issue_code TEXT,
            materials TEXT,
            last_comment TEXT,
            updated_at TEXT,
            accepted_at TEXT,
            started_at TEXT,
            completed_at TEXT,
            closed_at TEXT,
            ai_verdict TEXT,
            ai_score INTEGER
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity TEXT NOT NULL,
            event TEXT NOT NULL,
            user TEXT,
            details TEXT,
            created_at TEXT NOT NULL
        )
        """
    )

    conn.execute("INSERT OR IGNORE INTO roles (code, title) VALUES (?, ?)", ("master", "Мастер смены"))
    conn.execute("INSERT OR IGNORE INTO roles (code, title) VALUES (?, ?)", ("worker", "Исполнитель"))
    conn.execute("INSERT OR IGNORE INTO roles (code, title) VALUES (?, ?)", ("chief", "Руководитель"))
    conn.execute("INSERT OR IGNORE INTO roles (code, title) VALUES (?, ?)", ("admin", "Администратор"))

    default_site_data = [
        ("site_drob", "Дробление"),
        ("site_og", "Обогащение"),
        ("site_rmc", "Ремонтно-механический цех"),
        ("site_transport", "Транспортировка"),
    ]
    for code, title in default_site_data:
        conn.execute("INSERT OR IGNORE INTO sites (code, title) VALUES (?, ?)", (code, title))

    default_equipment = [
        ("site_drob", "К-1", "Конвейер К-1", "конвейер", "ok"),
        ("site_drob", "К-2", "Конвейер К-2", "конвейер", "ok"),
        ("site_drob", "К-3", "Конвейер К-3", "конвейер", "warning"),
        ("site_drob", "К-4", "Конвейер К-4", "конвейер", "ok"),
        ("site_drob", "К-5", "Конвейер К-5", "конвейер", "ok"),
        ("site_drob", "Д-1", "Дробилка Д-1", "дробилка", "ok"),
        ("site_drob", "Д-2", "Дробилка Д-2", "дробилка", "warning"),
        ("site_og", "Н-1", "Насос Н-1", "насос", "ok"),
        ("site_og", "Н-2", "Насос Н-2", "насос", "warning"),
        ("site_og", "Н-3", "Насос Н-3", "насос", "ok"),
        ("site_og", "Ф-1", "Фильтр Ф-1", "фильтр", "ok"),
        ("site_og", "М-1", "Мешалка М-1", "мешалка", "warning"),
        ("site_og", "П-1", "Печь П-1", "печь", "ok"),
        ("site_rmc", "РМ-1", "Станок РМ-1", "станок", "ok"),
        ("site_rmc", "РМ-2", "Станок РМ-2", "станок", "ok"),
        ("site_rmc", "С-1", "Сварочный пост С-1", "сварка", "ok"),
        ("site_rmc", "С-2", "Сварочный пост С-2", "сварка", "warning"),
        ("site_rmc", "Э-1", "Электрошкаф Э-1", "электро", "ok"),
        ("site_rmc", "Э-2", "Электрошкаф Э-2", "электро", "ok"),
        ("site_transport", "ТР-1", "Транспортёр ТР-1", "конвейер", "ok"),
        ("site_transport", "ТР-2", "Транспортёр ТР-2", "конвейер", "warning"),
        ("site_transport", "ТР-3", "Транспортёр ТР-3", "конвейер", "ok"),
        ("site_transport", "Л-1", "Лента Л-1", "лента", "ok"),
        ("site_transport", "Л-2", "Лента Л-2", "лента", "warning"),
        ("site_transport", "П-2", "Питатель П-2", "питатель", "ok"),
    ]
    for values in default_equipment:
        conn.execute(
            "INSERT OR IGNORE INTO equipment (site_code, code, title, type_group, status) VALUES (?, ?, ?, ?, ?)",
            values,
        )

    issue_codes = [
        ("M-01", "M", "Износ подшипника"),
        ("M-02", "M", "Подшипник вышел из строя"),
        ("M-03", "M", "Ослабление крепления"),
        ("E-01", "E", "Обрыв кабеля"),
        ("E-02", "E", "Неисправность автоматики"),
        ("G-01", "G", "Утечка масла"),
        ("G-02", "G", "Низкое давление"),
        ("P-01", "P", "Пневматический сбой"),
        ("S-01", "S", "Недостаточная смазка"),
        ("S-02", "S", "Загрязнение смазки"),
    ]
    for values in issue_codes:
        conn.execute("INSERT OR IGNORE INTO issue_codes (code, group_code, title) VALUES (?, ?, ?)", values)

    materials = [
        ("MAT-001", "Подшипник", "шт.", 1),
        ("MAT-002", "Сальник", "шт.", 1),
        ("MAT-003", "Прокладка", "шт.", 2),
        ("MAT-004", "Трубка 20 мм", "м", 3),
        ("MAT-005", "Трубка 40 мм", "м", 2),
        ("MAT-006", "Масло МГЕ-46", "л", 12),
        ("MAT-007", "Кабель ПВ-3", "м", 10),
        ("MAT-008", "Гофра", "м", 3),
        ("MAT-009", "Электрод 3 мм", "шт.", 20),
        ("MAT-010", "Паста смазочная", "кг", 1),
    ]
    for values in materials:
        conn.execute("INSERT OR IGNORE INTO materials (code, title, unit, standard_consumption) VALUES (?, ?, ?, ?)", values)

    default_tools = [
        ("TOOL-001", "Набор гаечных ключей", "компл."),
        ("TOOL-002", "Съёмник подшипников", "шт."),
        ("TOOL-003", "Мультиметр", "шт."),
        ("TOOL-004", "Набор отвёрток", "компл."),
        ("TOOL-005", "Таль ручная", "шт."),
        ("TOOL-006", "Домкрат", "шт."),
        ("TOOL-007", "Сварочный аппарат", "шт."),
        ("TOOL-008", "Шприц для смазки", "шт."),
    ]
    for values in default_tools:
        conn.execute("INSERT OR IGNORE INTO tools (code, title, unit) VALUES (?, ?, ?)", values)

    default_users = [
        ("master1", "Сергей Петров", "1111", "master", "Смена А", "free"),
        ("master2", "Арина Жукова", "1111", "master", "Смена Б", "free"),
        ("chief", "Илья Кондратьев", "1111", "chief", None, "free"),
        ("admin", "Марина Соколова", "1111", "admin", None, "free"),
        ("w01", "Ахметов Е.Ю.", "1111", "worker", "Бригада 1", "free"),
        ("w02", "Борисов Н.А.", "1111", "worker", "Бригада 1", "free"),
        ("w03", "Васильев К.И.", "1111", "worker", "Бригада 1", "busy"),
        ("w04", "Грачев Р.П.", "1111", "worker", "Бригада 1", "free"),
        ("w05", "Дмитриев В.М.", "1111", "worker", "Бригада 2", "free"),
        ("w06", "Егоров С.Л.", "1111", "worker", "Бригада 2", "busy"),
        ("w07", "Жирнов А.Т.", "1111", "worker", "Бригада 2", "free"),
        ("w08", "Зайцев И.Д.", "1111", "worker", "Бригада 2", "free"),
        ("w09", "Ковалев М.С.", "1111", "worker", "Бригада 3", "free"),
        ("w10", "Лапин П.В.", "1111", "worker", "Бригада 3", "free"),
        ("w11", "Миронов Д.Ф.", "1111", "worker", "Бригада 3", "busy"),
        ("w12", "Набоков И.Е.", "1111", "worker", "Бригада 3", "free"),
        ("w13", "Овчинников Н.Г.", "1111", "worker", "Бригада 1", "free"),
        ("w14", "Петров А.К.", "1111", "worker", "Бригада 2", "free"),
        ("w15", "Румянцев П.Л.", "1111", "worker", "Бригада 3", "off_duty"),
    ]
    if APP_ENV == "production":
        default_users = []
        bootstrap_username = os.getenv("BOOTSTRAP_ADMIN_USERNAME", "").strip()
        bootstrap_pin = os.getenv("BOOTSTRAP_ADMIN_PIN", "")
        if bootstrap_username or bootstrap_pin:
            if not bootstrap_username or len(bootstrap_pin) < 12:
                conn.close()
                raise RuntimeError("Production bootstrap requires BOOTSTRAP_ADMIN_USERNAME and a BOOTSTRAP_ADMIN_PIN of at least 12 characters")
            default_users.append((bootstrap_username, "Администратор", bootstrap_pin, "admin", None, "free"))
        elif conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            conn.close()
            raise RuntimeError("Set BOOTSTRAP_ADMIN_USERNAME and BOOTSTRAP_ADMIN_PIN to initialize the production administrator")

    for username, full_name, pin, role_code, team, status in default_users:
        conn.execute(
            "INSERT OR IGNORE INTO users (username, full_name, pin, role_code, team, status) VALUES (?, ?, ?, ?, ?, ?)",
            (username, full_name, hash_pin(pin), role_code, team, status),
        )

    sample_orders = [
        (101, "site_drob", "К-3", "urgent", "issued", "w01", "Протечка масла на конвейере", "На участке видна масляная лужа и следы износа ролика", "2026-10-01 08:00:00", "2026-10-01 10:00:00", "unplanned"),
        (102, "site_og", "Н-2", "high", "in_progress", "w05", "Снижение давления в насосе", "Насос работает с перебоями, требуется замена сальника", "2026-10-01 09:20:00", "2026-10-01 17:20:00", "planned"),
        (103, "site_transport", "ТР-2", "normal", "queued", "w08", "Шум в редукторе", "Проверить натяжение и состояние подшипников", "2026-10-01 11:00:00", "2026-10-01 22:00:00", "planned"),
        (104, "site_rmc", "Э-1", "urgent", "done", "w11", "Сбой защиты", "Провести диагностику и исправить ошибку в шкафу", "2026-10-01 12:00:00", "2026-10-01 14:00:00", "unplanned"),
    ]
    if APP_ENV != "production":
        for values in sample_orders:
            conn.execute(
                "INSERT OR IGNORE INTO work_orders (number, site_code, equipment_code, priority, status, executor_user, title, description, created_at, due_at, type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                values,
            )

    conn.execute(
        "INSERT OR IGNORE INTO audit_log (entity, event, user, details, created_at) VALUES (?, ?, ?, ?, ?)",
        ("system", "boot", "system", "База данных и справочники инициализированы", "2026-10-01 00:00:00"),
    )

    conn.commit()
    conn.close()
    ensure_columns()


def log_event(work_order_id: int | None, event: str, user: str | None, reason: str | None, details: str | None) -> None:
    conn = get_connection()
    conn.execute(
        "INSERT INTO work_order_events (work_order_id, event, user, reason, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (work_order_id, event, user, reason, details, now_iso()),
    )
    conn.commit()
    conn.close()


async def notify_clients(message: dict[str, Any]) -> None:
    await manager.broadcast(message)


def _deadline_risk(due_at: str | None, status: str | None) -> tuple[str, float]:
    if not due_at:
        return "low", 0.0

    try:
        due = datetime.strptime(due_at, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return "low", 0.0

    if status in {"done", "closed"}:
        return "low", 0.0

    delta_hours = (due - datetime.now()).total_seconds() / 3600.0
    if delta_hours < -12:
        return "critical", delta_hours
    if delta_hours < -6:
        return "high", delta_hours
    if delta_hours < 0:
        return "medium", delta_hours
    return "low", delta_hours


def _claude_analysis(order: dict[str, Any]) -> dict[str, Any] | None:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return None

    prompt = (
        "Ты — проверяющий инженер. Ответь строго JSON без комментариев. "
        "Проверь работу: "
        f"priority={order.get('priority')}, status={order.get('status')}, equipment={order.get('equipment_code')}, "
        f"site={order.get('site_code')}, title={order.get('title')}, description={order.get('description')}, "
        f"reason={order.get('reason')}, due_at={order.get('due_at')}. "
        "Верни поля: ai_verdict, ai_score, risk_comment. "
        "Нормируй оценку 0-100."
    )
    request_body = {
        "model": os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022"),
        "max_tokens": 256,
        "messages": [{"role": "user", "content": prompt}],
    }

    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }

    try:
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(request_body).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=12) as response:
            payload = json.loads(response.read().decode("utf-8"))
        text = payload.get("content", [{}])[0].get("text", "")
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return {
                "mode": "claude",
                "ai_verdict": parsed.get("ai_verdict") or "требует проверки",
                "ai_score": int(parsed.get("ai_score", 70)),
                "risk_comment": parsed.get("risk_comment") or "AI-оценка проведена",
            }
    except (urllib.error.URLError, ValueError, KeyError, TypeError, IndexError):
        return None

    return None


def analyze_work_order(work_order_id: int) -> dict[str, Any]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM work_orders WHERE id = ?", (work_order_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Наряд не найден")

    order = dict(row)
    due_risk, hours_left = _deadline_risk(order.get("due_at"), order.get("status"))
    base_score = 88
    if order.get("priority") in {"urgent", "high"}:
        base_score -= 12
    if order.get("status") in {"paused", "queued", "rejected"}:
        base_score -= 18
    if due_risk in {"high", "critical"}:
        base_score -= 22 if due_risk == "high" else 35
    if "доработка" in (order.get("title") or "").lower() or "повтор" in (order.get("description") or "").lower():
        base_score -= 12
    if "ночная" in (order.get("title") or "").lower() or "ночная" in (order.get("description") or "").lower():
        base_score -= 8

    score = max(0, min(100, base_score))
    verdict = "подтверждено"
    if score < 60:
        verdict = "критично"
    elif score < 75:
        verdict = "требует вмешательства"
    elif score < 85:
        verdict = "с ограничениями"

    ai_result = _claude_analysis(order)
    if ai_result is None:
        ai_result = {
            "mode": "fallback",
            "ai_verdict": verdict,
            "ai_score": score,
            "risk_comment": (
                "Резервный режим: проверка выполнена локально. "
                f"Срок риска={due_risk}, до дедлайна {hours_left:.1f} часов."
            ),
        }

    ai_result["order_id"] = int(work_order_id)
    ai_result["deadline_risk"] = due_risk
    ai_result["hours_left"] = round(hours_left, 1)
    ai_result["status"] = order.get("status")
    ai_result["priority"] = order.get("priority")
    ai_result["equipment_code"] = order.get("equipment_code")
    ai_result["due_at"] = order.get("due_at")
    conn.close()
    return ai_result


def get_ai_overview() -> dict[str, Any]:
    conn = get_connection()
    overdue_count = conn.execute(
        "SELECT COUNT(*) FROM work_orders WHERE status NOT IN ('done', 'closed') AND due_at IS NOT NULL AND due_at < ?",
        (now_iso(),),
    ).fetchone()[0]
    urgent_count = conn.execute(
        "SELECT COUNT(*) FROM work_orders WHERE priority IN ('urgent', 'high') AND status NOT IN ('done', 'closed')"
    ).fetchone()[0]
    items = conn.execute(
        "SELECT id, number, equipment_code, priority, status, due_at FROM work_orders WHERE status NOT IN ('done', 'closed') ORDER BY CASE priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END, due_at ASC LIMIT 12"
    ).fetchall()
    conn.close()
    return {
        "overdue_count": overdue_count,
        "urgent_count": urgent_count,
        "items": [dict(item) for item in items],
    }


def get_report_summary() -> dict[str, Any]:
    conn = get_connection()
    summary = {
        "orders_total": conn.execute("SELECT COUNT(*) FROM work_orders").fetchone()[0],
        "open_orders": conn.execute("SELECT COUNT(*) FROM work_orders WHERE status NOT IN ('done', 'closed')").fetchone()[0],
        "overdue_orders": conn.execute("SELECT COUNT(*) FROM work_orders WHERE status NOT IN ('done', 'closed') AND due_at IS NOT NULL AND due_at < ?", (now_iso(),)).fetchone()[0],
        "avg_score": conn.execute("SELECT COALESCE(AVG(ai_score), 0) FROM work_orders WHERE ai_score IS NOT NULL").fetchone()[0],
        "top_equipment": [dict(item) for item in conn.execute("SELECT equipment_code, COUNT(*) AS count FROM work_orders GROUP BY equipment_code ORDER BY count DESC LIMIT 5").fetchall()],
        "status_breakdown": [dict(item) for item in conn.execute("SELECT status, COUNT(*) AS count FROM work_orders GROUP BY status ORDER BY count DESC").fetchall()],
        "urgent_items": [dict(item) for item in conn.execute("SELECT id, number, equipment_code, priority, status, due_at FROM work_orders WHERE priority IN ('urgent', 'high') AND status NOT IN ('done', 'closed') ORDER BY due_at ASC LIMIT 8").fetchall()],
    }
    conn.close()
    return summary


def seed_history_data() -> None:
    conn = get_connection()
    existing_total = conn.execute("SELECT COUNT(*) FROM work_orders").fetchone()[0]
    if existing_total >= 500:
        conn.close()
        return

    start_day = datetime(2026, 7, 8, 8, 0, 0)
    equipment_rows = conn.execute("SELECT code, title, site_code FROM equipment ORDER BY code").fetchall()
    equipment_map = [dict(item) for item in equipment_rows]
    worker_rows = conn.execute("SELECT username, full_name, team FROM users WHERE role_code = 'worker' ORDER BY username").fetchall()
    worker_list = [dict(item) for item in worker_rows]
    night_workers = {"w09", "w10", "w11", "w12"}

    planned_shifts = {
        "site_drob": ["К-3", "К-2", "К-1", "Д-2"],
        "site_og": ["Н-2", "Н-1", "Ф-1", "М-1"],
        "site_transport": ["ТР-2", "ТР-1", "Л-2", "П-2"],
        "site_rmc": ["Э-1", "С-2", "РМ-1", "С-1"],
    }
    rng = random.Random(42)
    order_number = 200

    for day_index in range(90):
        current_day = start_day + timedelta(days=day_index)
        base_count = 5 + (day_index % 4)

        for idx in range(base_count):
            if rng.random() < 0.24:
                equipment_code = "К-3"
                title = "Поломка конвейера К-3"
                description = "Повторное повреждение на линии дробления, требуется срочный осмотр и замена подшипника."
                priority = "urgent"
                issue_code = "M-02"
                site_code = "site_drob"
            elif rng.random() < 0.13:
                equipment_code = "Н-2"
                title = "Снижение давления в насосе Н-2"
                description = "после планового ремонта снова отмечены рывки и утечки до ремонта."
                priority = "high"
                issue_code = "G-01"
                site_code = "site_og"
            elif rng.random() < 0.12:
                equipment_code = "ТР-2"
                title = "Шум в редукторе транспортёра"
                description = "Сильный шум и вибрация на транспортёре, возможен износ подшипника."
                priority = "normal"
                issue_code = "M-01"
                site_code = "site_transport"
            elif rng.random() < 0.15:
                equipment_code = "Э-1"
                title = "Сбой защитного автомата"
                description = "Неисправность в щите управления и повторный сброс цепи защиты."
                priority = "high"
                issue_code = "E-02"
                site_code = "site_rmc"
            else:
                available = equipment_map.copy()
                ordered = sorted(available, key=lambda item: item["code"] == "К-3", reverse=True)
                target = rng.choice(ordered[:10])
                equipment_code = target["code"]
                site_code = target["site_code"]
                issue_code = rng.choice(["M-03", "G-02", "S-01", "P-01", "E-01"])
                title = f"Неисправность {equipment_code}"
                description = f"Оборудование {equipment_code} требует осмотра и устранения дефекта."
                priority = rng.choice(["normal", "high"])

            if day_index % 7 == 0 and rng.random() < 0.5:
                description += " Возврат на доработку: после осмотра нужна повторная проверка качества."
                title = f"Доработка {equipment_code}"
                priority = "high"

            if idx % 6 == 0 and rng.random() < 0.7:
                description += " ночная смена: материал списан сверх нормы после замены и требуется сверка с расходом."
                title = f"Ночная проверка {equipment_code}"

            worker = rng.choice(worker_list)
            if day_index % 8 == 0 and rng.random() < 0.5:
                worker = next((w for w in worker_list if w["username"] == "w06"), worker)
            if idx % 5 == 0 and rng.random() < 0.9:
                worker = next((w for w in worker_list if w["username"] == "w11"), worker)

            created_dt = current_day + timedelta(hours=7 + idx, minutes=rng.randint(0, 45))
            due_dt = created_dt + timedelta(hours={"urgent": 2, "high": 8, "normal": 24}[priority])
            type_value = "unplanned" if priority == "urgent" else "planned"
            status = rng.choice(["issued", "in_progress", "queued", "done", "closed"])
            if idx % 9 == 0:
                status = "closed"
            if idx % 11 == 0:
                status = "in_progress"

            conn.execute(
                """
                INSERT INTO work_orders (number, site_code, equipment_code, priority, status, executor_user, title, description, created_at, due_at, type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    order_number,
                    site_code,
                    equipment_code,
                    priority,
                    status,
                    worker["username"],
                    title,
                    description,
                    created_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    due_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    type_value,
                ),
            )
            order_number += 1

    conn.execute(
        "UPDATE work_orders SET description = COALESCE(description, '') || ' после планового ремонта.' WHERE equipment_code = 'Н-2' AND id % 5 = 0"
    )
    conn.execute(
        "UPDATE work_orders SET description = COALESCE(description, '') || ' ночная смена: материал списан сверх нормы.' WHERE executor_user IN ('w09', 'w10', 'w11', 'w12') AND id % 4 = 0"
    )
    conn.execute(
        "UPDATE work_orders SET title = 'Доработка ' || equipment_code, description = COALESCE(description, '') || ' возврат на доработку.' WHERE executor_user = 'w11' AND id % 3 = 0"
    )
    conn.execute(
        "UPDATE work_orders SET title = 'Повторный отказ на конвейере К-3', description = COALESCE(description, '') || ' повторная неисправность на конвейере К-3.' WHERE equipment_code = 'К-3' AND id % 2 = 0"
    )
    conn.execute(
        "INSERT OR IGNORE INTO audit_log (entity, event, user, details, created_at) VALUES (?, ?, ?, ?, ?)",
        ("system", "historical_seed", "system", "Сгенерирована история за 3 месяца и аномалии для демо-защиты", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    )
    conn.commit()
    conn.close()


init_db()
if APP_ENV == "production":
    conn = get_connection()
    demo_users = conn.execute("SELECT username, pin FROM users WHERE username IN ('master1', 'master2', 'chief', 'admin', 'w01', 'w02', 'w03', 'w04', 'w05', 'w06', 'w07', 'w08', 'w09', 'w10', 'w11', 'w12', 'w13', 'w14', 'w15')").fetchall()
    has_demo_pin = any(verify_pin(row["pin"], "1111") for row in demo_users)
    has_demo_history = conn.execute("SELECT 1 FROM audit_log WHERE event = 'historical_seed' LIMIT 1").fetchone()
    conn.close()
    if has_demo_pin or has_demo_history:
        raise RuntimeError("Production cannot start with default demo PINs or generated demo history; configure a clean DATABASE_PATH")
else:
    seed_history_data()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    if not get_session_user(websocket.cookies.get(SESSION_COOKIE_NAME)):
        await websocket.close(code=1008)
        return
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.get("/")
def read_index() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok"}


@app.get("/api/roles")
def get_roles() -> dict[str, Any]:
    conn = get_connection()
    rows = conn.execute("SELECT code, title FROM roles ORDER BY title").fetchall()
    conn.close()
    return {"items": [dict(row) for row in rows]}


@app.post("/api/login")
def login(payload: LoginRequest, request: Request, response: Response) -> dict[str, Any]:
    client_ip = request.client.host if request.client else "unknown"
    attempt_key = f"{client_ip}:{payload.username.strip().lower()}"
    if login_is_locked(attempt_key):
        raise HTTPException(status_code=429, detail="Слишком много попыток. Повторите вход через 10 минут")

    conn = get_connection()
    row = conn.execute(
        "SELECT u.id, u.username, u.full_name, u.pin, u.role_code, r.title AS role_title, u.team, u.status FROM users u LEFT JOIN roles r ON r.code = u.role_code WHERE u.username = ?",
        (payload.username,),
    ).fetchone()
    if not row:
        conn.close()
        record_failed_login(attempt_key)
        raise HTTPException(status_code=401, detail="Неверный логин или PIN")
    if not verify_pin(row["pin"], payload.pin):
        conn.close()
        record_failed_login(attempt_key)
        raise HTTPException(status_code=401, detail="Неверный логин или PIN")

    clear_login_failures(attempt_key)

    if not row["pin"].startswith("pbkdf2_sha256$"):
        conn.execute("UPDATE users SET pin = ? WHERE id = ?", (hash_pin(payload.pin), row["id"]))

    user = {
        "id": row["id"],
        "username": row["username"],
        "full_name": row["full_name"],
        "role": row["role_code"],
        "role_title": row["role_title"],
        "team": row["team"],
        "status": row["status"],
    }
    token = create_session(conn, row["id"])
    conn.commit()
    conn.close()
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=SESSION_COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    return {"ok": True, "user": user}


@app.get("/api/session")
def get_current_session(request: Request) -> dict[str, Any]:
    return {"ok": True, "user": request.state.user}


@app.post("/api/logout")
def logout(request: Request, response: Response) -> dict[str, bool]:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        conn = get_connection()
        conn.execute("DELETE FROM user_sessions WHERE token_hash = ?", (session_token_hash(token),))
        conn.commit()
        conn.close()
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        httponly=True,
        secure=SESSION_COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    return {"ok": True}


@app.get("/api/users")
def get_users(request: Request) -> dict[str, Any]:
    if request.state.user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Управлять пользователями может только администратор")
    conn = get_connection()
    rows = conn.execute(
        "SELECT u.username, u.full_name, u.role_code, r.title AS role_title, u.team, u.status FROM users u LEFT JOIN roles r ON r.code = u.role_code ORDER BY r.title, u.full_name"
    ).fetchall()
    conn.close()
    return {"items": [dict(row) for row in rows]}


@app.post("/api/users")
def create_user(payload: UserCreateRequest, request: Request) -> dict[str, Any]:
    if request.state.user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Создавать пользователей может только администратор")
    if payload.role_code not in {"master", "worker", "chief"}:
        raise HTTPException(status_code=422, detail="Недопустимая роль пользователя")

    username = payload.username.strip().lower()
    full_name = payload.full_name.strip()
    team = payload.team.strip()
    if not full_name:
        raise HTTPException(status_code=422, detail="Укажите имя сотрудника")

    conn = get_connection()
    exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
    if exists:
        conn.close()
        raise HTTPException(status_code=409, detail="Пользователь с таким логином уже существует")
    conn.execute(
        "INSERT INTO users (username, full_name, pin, role_code, team, status) VALUES (?, ?, ?, ?, ?, 'free')",
        (username, full_name, hash_pin(payload.pin), payload.role_code, team or None),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "username": username}


@app.get("/api/resources")
def get_resources() -> dict[str, Any]:
    conn = get_connection()
    materials = conn.execute("SELECT code, title, unit FROM materials ORDER BY title").fetchall()
    tools = conn.execute("SELECT code, title, unit FROM tools ORDER BY title").fetchall()
    conn.close()
    items = [
        {**dict(item), "resource_type": resource_type}
        for resource_type, rows in (("material", materials), ("tool", tools))
        for item in rows
    ]
    return {"items": items}


@app.post("/api/resources")
def create_resource(payload: ResourceCreateRequest, request: Request) -> dict[str, Any]:
    if request.state.user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Изменять каталог ресурсов может только администратор")
    if payload.resource_type not in {"material", "tool"}:
        raise HTTPException(status_code=422, detail="Тип ресурса должен быть material или tool")

    code = payload.code.strip().upper()
    title = payload.title.strip()
    unit = payload.unit.strip()
    if not title or not unit:
        raise HTTPException(status_code=422, detail="Укажите название и единицу измерения")

    conn = get_connection()
    table_name = "materials" if payload.resource_type == "material" else "tools"
    exists = conn.execute(f"SELECT 1 FROM {table_name} WHERE code = ?", (code,)).fetchone()
    if exists:
        conn.close()
        raise HTTPException(status_code=409, detail="Код ресурса уже существует в каталоге")
    conn.execute(
        f"INSERT INTO {table_name} (code, title, unit) VALUES (?, ?, ?)",
        (code, title, unit),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "code": code, "resource_type": payload.resource_type}


@app.get("/api/dashboard/{role}")
def get_dashboard(role: str, request: Request) -> dict[str, Any]:
    if role != request.state.user["role"] and request.state.user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Нет доступа к панели этой роли")
    conn = get_connection()
    role_rows = conn.execute("SELECT title FROM roles WHERE code = ?", (role,)).fetchone()
    if not role_rows:
        conn.close()
        raise HTTPException(status_code=404, detail="Роль не найдена")

    if role == "master":
        workers = conn.execute(
            "SELECT username, full_name, team, status FROM users WHERE role_code = 'worker' ORDER BY full_name"
        ).fetchall()
        sites = conn.execute("SELECT code, title FROM sites ORDER BY title").fetchall()
        equipment_count = conn.execute("SELECT COUNT(*) FROM equipment").fetchone()[0]
        active_orders = conn.execute("SELECT COUNT(*) FROM work_orders WHERE status IN ('issued', 'in_progress', 'queued', 'done')").fetchone()[0]
        work_orders = conn.execute(
            "SELECT id, number, site_code, equipment_code, priority, status, executor_user, title, description, comment, created_at, due_at, photo_before, photo_after, reason, last_comment FROM work_orders ORDER BY id DESC LIMIT 40"
        ).fetchall()
        ai_overview = get_ai_overview()
        summary = {
            "role_title": role_rows["title"],
            "workers": [dict(item) for item in workers],
            "sites": [dict(item) for item in sites],
            "equipment_count": equipment_count,
            "active_orders": active_orders,
            "work_orders": [dict(item) for item in work_orders],
            "ai_overview": ai_overview,
        }
    elif role == "worker":
        user_rows = conn.execute(
            "SELECT username, full_name, team FROM users WHERE role_code = 'worker' ORDER BY username LIMIT 15"
        ).fetchall()
        tasks = conn.execute(
            "SELECT id, number, title, status, priority, equipment_code, created_at, description, comment, due_at, issue_code FROM work_orders WHERE executor_user = ? ORDER BY id DESC LIMIT 20",
            (request.state.user["username"],),
        ).fetchall()
        summary = {
            "role_title": role_rows["title"],
            "workers": [dict(item) for item in user_rows],
            "tasks": [dict(item) for item in tasks],
            "issue_codes": [dict(item) for item in conn.execute("SELECT code, title FROM issue_codes ORDER BY code").fetchall()],
        }
    elif role == "chief":
        report = get_report_summary()
        summary = {
            "role_title": role_rows["title"],
            "equipment_total": conn.execute("SELECT COUNT(*) FROM equipment").fetchone()[0],
            "orders_total": conn.execute("SELECT COUNT(*) FROM work_orders").fetchone()[0],
            "problem_sites": conn.execute("SELECT code, title FROM sites ORDER BY title LIMIT 4").fetchall(),
            "ai_overview": get_ai_overview(),
            "report": report,
        }
    elif role == "admin":
        summary = {
            "role_title": role_rows["title"],
            "sites": [dict(item) for item in conn.execute("SELECT code, title FROM sites ORDER BY title").fetchall()],
            "materials": [dict(item) for item in conn.execute("SELECT code, title, unit FROM materials ORDER BY title LIMIT 6").fetchall()],
            "issue_codes": [dict(item) for item in conn.execute("SELECT code, group_code, title FROM issue_codes ORDER BY code LIMIT 8").fetchall()],
        }
    else:
        conn.close()
        raise HTTPException(status_code=404, detail="Роль не поддерживается")

    conn.close()
    return summary


@app.get("/api/ai/check/{work_order_id}")
def get_ai_check(work_order_id: int) -> dict[str, Any]:
    return analyze_work_order(work_order_id)


@app.get("/api/ai/overview")
def get_ai_overview_route() -> dict[str, Any]:
    return get_ai_overview()


@app.get("/api/reports/summary")
def get_report_route() -> dict[str, Any]:
    return get_report_summary()


@app.get("/api/reports/export")
def export_report_csv() -> Response:
    summary = get_report_summary()
    csv_lines = [
        "metric,value",
        f"orders_total,{summary['orders_total']}",
        f"open_orders,{summary['open_orders']}",
        f"overdue_orders,{summary['overdue_orders']}",
        f"avg_score,{summary['avg_score']}",
    ]
    for item in summary["top_equipment"]:
        csv_lines.append(f"top_equipment,{item['equipment_code']},{item['count']}")
    payload = "\n".join(csv_lines)
    return Response(content=payload, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=report.csv"})


@app.get("/api/training/dataset")
def export_training_dataset() -> Response:
    fields = [
        "work_order_id",
        "site_code",
        "equipment_code",
        "work_type",
        "priority",
        "issue_code",
        "created_at",
        "due_hours_from_start",
        "planned_crew_size",
        "actual_crew_size",
        "actual_duration_hours",
        "planned_materials_json",
        "planned_tools_json",
        "actual_materials_json",
        "actual_tools_json",
    ]
    conn = get_connection()
    orders = conn.execute(
        """
        SELECT id, site_code, equipment_code, type, priority, issue_code,
               created_at, due_at, started_at, completed_at,
               planned_crew_size, actual_crew_size
        FROM work_orders
        WHERE started_at IS NOT NULL AND completed_at IS NOT NULL
          AND planned_crew_size IS NOT NULL AND actual_crew_size IS NOT NULL
        ORDER BY completed_at, id
        """
    ).fetchall()
    resource_rows = conn.execute(
        """
        SELECT resource_items.work_order_id, resource_items.phase,
               resource_items.resource_type, resource_items.resource_code,
               resource_items.quantity, resource_items.unit
        FROM work_order_resource_items AS resource_items
        JOIN work_orders AS orders ON orders.id = resource_items.work_order_id
        WHERE orders.started_at IS NOT NULL AND orders.completed_at IS NOT NULL
          AND orders.planned_crew_size IS NOT NULL AND orders.actual_crew_size IS NOT NULL
        ORDER BY resource_items.work_order_id, resource_items.id
        """
    ).fetchall()
    conn.close()

    resources_by_order: dict[int, dict[str, list[dict[str, Any]]]] = {}
    for item in resource_rows:
        order_resources = resources_by_order.setdefault(
            item["work_order_id"],
            {"planned_material": [], "planned_tool": [], "actual_material": [], "actual_tool": []},
        )
        key = f"{item['phase']}_{item['resource_type']}"
        order_resources[key].append({
            "code": item["resource_code"],
            "quantity": item["quantity"],
            "unit": item["unit"],
        })

    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for order in orders:
        try:
            started_at = datetime.fromisoformat(order["started_at"])
            completed_at = datetime.fromisoformat(order["completed_at"])
            created_at = datetime.fromisoformat(order["created_at"])
            due_at = datetime.fromisoformat(order["due_at"]) if order["due_at"] else None
        except (TypeError, ValueError):
            continue
        duration_seconds = (completed_at - started_at).total_seconds()
        if duration_seconds < MIN_TRAINING_DURATION_SECONDS:
            continue
        duration_hours = duration_seconds / 3600
        order_resources = resources_by_order.get(
            order["id"],
            {"planned_material": [], "planned_tool": [], "actual_material": [], "actual_tool": []},
        )
        writer.writerow({
            "work_order_id": order["id"],
            "site_code": order["site_code"],
            "equipment_code": order["equipment_code"],
            "work_type": order["type"],
            "priority": order["priority"],
            "issue_code": order["issue_code"] or "",
            "created_at": created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "due_hours_from_start": round((due_at - started_at).total_seconds() / 3600, 2) if due_at else "",
            "planned_crew_size": order["planned_crew_size"],
            "actual_crew_size": order["actual_crew_size"],
            "actual_duration_hours": round(duration_hours, 6),
            "planned_materials_json": json.dumps(order_resources["planned_material"], ensure_ascii=False),
            "planned_tools_json": json.dumps(order_resources["planned_tool"], ensure_ascii=False),
            "actual_materials_json": json.dumps(order_resources["actual_material"], ensure_ascii=False),
            "actual_tools_json": json.dumps(order_resources["actual_tool"], ensure_ascii=False),
        })

    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=work-order-training-v1.csv"},
    )


@app.get("/api/summary")
def get_summary() -> dict[str, Any]:
    conn = get_connection()
    data = {
        "users_total": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "sites_total": conn.execute("SELECT COUNT(*) FROM sites").fetchone()[0],
        "equipment_total": conn.execute("SELECT COUNT(*) FROM equipment").fetchone()[0],
        "orders_total": conn.execute("SELECT COUNT(*) FROM work_orders").fetchone()[0],
        "issue_codes_total": conn.execute("SELECT COUNT(*) FROM issue_codes").fetchone()[0],
        "materials_total": conn.execute("SELECT COUNT(*) FROM materials").fetchone()[0],
    }
    conn.close()
    return data


@app.get("/api/test-data")
def get_test_data() -> dict[str, Any]:
    conn = get_connection()
    users = conn.execute("SELECT username, full_name, role_code FROM users ORDER BY username").fetchall()
    conn.close()
    return {"items": [dict(item) for item in users]}


@app.get("/api/sites")
def get_sites() -> dict[str, Any]:
    conn = get_connection()
    rows = conn.execute("SELECT code, title FROM sites ORDER BY title").fetchall()
    conn.close()
    return {"items": [dict(item) for item in rows]}


@app.get("/api/equipment")
def get_equipment(site_code: str | None = None) -> dict[str, Any]:
    conn = get_connection()
    if site_code:
        rows = conn.execute(
            "SELECT code, title, site_code FROM equipment WHERE site_code = ? ORDER BY code",
            (site_code,),
        ).fetchall()
    else:
        rows = conn.execute("SELECT code, title, site_code FROM equipment ORDER BY code").fetchall()
    conn.close()
    return {"items": [dict(item) for item in rows]}


@app.get("/api/workers")
def get_workers() -> dict[str, Any]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT username, full_name, team, status FROM users WHERE role_code = 'worker' ORDER BY full_name"
    ).fetchall()
    conn.close()
    return {"items": [dict(item) for item in rows]}


@app.get("/api/work-orders")
def get_work_orders(request: Request, username: str | None = None, worker: str | None = None) -> dict[str, Any]:
    current_user = request.state.user
    if current_user["role"] == "worker":
        if username and username != current_user["username"]:
            raise HTTPException(status_code=403, detail="Можно просматривать только свои наряды")
        username = current_user["username"]

    conn = get_connection()
    if username:
        rows = conn.execute(
            "SELECT * FROM work_orders WHERE executor_user = ? ORDER BY id DESC",
            (username,),
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM work_orders ORDER BY id DESC LIMIT 50").fetchall()
    conn.close()
    return {"items": [dict(item) for item in rows]}


@app.post("/api/work-orders")
async def create_work_order(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    if request.state.user["role"] not in {"master", "admin"}:
        raise HTTPException(status_code=403, detail="Выдавать наряды может только мастер")

    planned_crew_size = payload.get("planned_crew_size")
    planned_material_items = normalize_resource_items(payload.get("planned_materials"), "плановые материалы", "material")
    planned_tool_items = normalize_resource_items(payload.get("planned_tools"), "плановые инструменты", "tool")
    planned_materials = encode_resource_items(planned_material_items)
    planned_tools = encode_resource_items(planned_tool_items)
    if not isinstance(planned_crew_size, int) or isinstance(planned_crew_size, bool) or not 1 <= planned_crew_size <= 100:
        raise HTTPException(status_code=422, detail="Укажите плановый размер бригады от 1 до 100 человек")
    site_code = payload.get("site_code")
    equipment_code = payload.get("equipment_code")
    priority = payload.get("priority", "normal")
    executor_user = payload.get("executor_user")
    title = payload.get("title") or "Новый наряд"
    description = payload.get("description") or ""
    comment = payload.get("comment") or ""
    photo_before = payload.get("photo_before") or ""
    created_at = now_iso()
    due_at = (datetime.now() + timedelta(hours={"urgent": 2, "high": 8, "normal": 24, "planned": 24}[priority])).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    next_number = conn.execute("SELECT COALESCE(MAX(number), 0) + 1 FROM work_orders").fetchone()[0]
    cursor = conn.execute(
        """
        INSERT INTO work_orders (number, site_code, equipment_code, priority, status, executor_user, title, description, comment, photo_before, created_at, due_at, type, updated_at, last_comment, planned_crew_size, planned_materials, planned_tools)
        VALUES (?, ?, ?, ?, 'issued', ?, ?, ?, ?, ?, ?, ?, 'planned', ?, ?, ?, ?, ?)
        """,
        (next_number, site_code, equipment_code, priority, executor_user, title, description, comment, photo_before, created_at, due_at, created_at, comment, planned_crew_size, planned_materials, planned_tools),
    )
    work_order_id = cursor.lastrowid
    save_resource_items(conn, work_order_id, "planned", "material", planned_material_items)
    save_resource_items(conn, work_order_id, "planned", "tool", planned_tool_items)
    conn.commit()
    conn.close()

    log_event(work_order_id, "issued", executor_user or "master1", "Выдан наряд", description)
    await notify_clients({"type": "dashboard_update", "role": "master"})
    await notify_clients({"type": "worker_update", "username": executor_user})
    return {"ok": True, "id": work_order_id, "number": next_number}


@app.post("/api/work-orders/{work_order_id}/action")
async def work_order_action(work_order_id: int, payload: dict[str, Any], request: Request) -> dict[str, Any]:
    action = payload.get("action")
    current_user = request.state.user
    executor_user = current_user["username"]
    reason = payload.get("reason")
    comment = payload.get("comment") or ""
    photo_after = payload.get("photo_after") or ""
    issue_code = payload.get("issue_code") or ""
    now = now_iso()

    conn = get_connection()
    row = conn.execute("SELECT * FROM work_orders WHERE id = ?", (work_order_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Наряд не найден")

    if current_user["role"] == "worker":
        worker_actions = {"accept", "queue", "reject", "start", "pause", "complete"}
        if action not in worker_actions or row["executor_user"] != executor_user:
            conn.close()
            raise HTTPException(status_code=403, detail="Нельзя изменять этот наряд")
    elif action != "close" or current_user["role"] not in {"master", "chief", "admin"}:
        conn.close()
        raise HTTPException(status_code=403, detail="Недостаточно прав для этого действия")

    new_status = row["status"]
    if action == "accept":
        new_status = "accepted"
        conn.execute("UPDATE work_orders SET status = ?, executor_user = ?, accepted_at = ?, updated_at = ?, last_comment = ? WHERE id = ?", (new_status, executor_user or row["executor_user"], now, now, comment or "Принят в работу", work_order_id))
    elif action == "queue":
        new_status = "queued"
        conn.execute("UPDATE work_orders SET status = ?, reason = ?, updated_at = ?, last_comment = ? WHERE id = ?", (new_status, reason or "В очереди", now, comment or "Поставлен в очередь", work_order_id))
    elif action == "reject":
        if not reason:
            conn.close(); raise HTTPException(status_code=400, detail="Причина отклонения обязательна")
        new_status = "rejected"
        conn.execute("UPDATE work_orders SET status = ?, reason = ?, updated_at = ?, last_comment = ? WHERE id = ?", (new_status, reason, now, comment or reason, work_order_id))
    elif action == "start":
        new_status = "in_progress"
        started_at = precise_now_iso()
        conn.execute("UPDATE work_orders SET status = ?, started_at = ?, updated_at = ?, last_comment = ? WHERE id = ?", (new_status, started_at, now, comment or "Начато исполнение", work_order_id))
    elif action == "pause":
        if not reason:
            conn.close(); raise HTTPException(status_code=400, detail="Причина приостановки обязательна")
        new_status = "paused"
        conn.execute("UPDATE work_orders SET status = ?, reason = ?, updated_at = ?, last_comment = ? WHERE id = ?", (new_status, reason, now, comment or reason, work_order_id))
    elif action == "complete":
        if row["status"] != "in_progress" or not row["started_at"]:
            conn.close()
            raise HTTPException(status_code=409, detail="Сначала начните выполнение наряда")
        actual_crew_size = payload.get("actual_crew_size")
        issue_code = str(issue_code).strip().upper()
        issue_exists = conn.execute("SELECT 1 FROM issue_codes WHERE code = ?", (issue_code,)).fetchone()
        if not issue_exists:
            conn.close()
            raise HTTPException(status_code=422, detail="Выберите код неисправности из справочника")
        actual_material_items = normalize_resource_items(payload.get("materials"), "фактические материалы", "material")
        actual_tool_items = normalize_resource_items(payload.get("tools_used"), "фактические инструменты", "tool")
        materials = encode_resource_items(actual_material_items)
        tools_used = encode_resource_items(actual_tool_items)
        if not isinstance(actual_crew_size, int) or isinstance(actual_crew_size, bool) or not 1 <= actual_crew_size <= 100:
            conn.close()
            raise HTTPException(status_code=422, detail="Укажите фактический размер бригады от 1 до 100 человек")
        new_status = "done"
        completed_at = precise_now_iso()
        conn.execute(
            "UPDATE work_orders SET status = ?, completed_at = ?, updated_at = ?, photo_after = ?, issue_code = ?, materials = ?, actual_crew_size = ?, tools_used = ?, last_comment = ?, comment = ? WHERE id = ?",
            (new_status, completed_at, now, photo_after, issue_code, materials, actual_crew_size, tools_used, comment or "Закрыт исполнителем", comment or "", work_order_id),
        )
        save_resource_items(conn, work_order_id, "actual", "material", actual_material_items)
        save_resource_items(conn, work_order_id, "actual", "tool", actual_tool_items)
    elif action == "close":
        new_status = "closed"
        conn.execute(
            "UPDATE work_orders SET status = ?, closed_at = ?, updated_at = ?, ai_verdict = ?, ai_score = ?, last_comment = ? WHERE id = ?",
            (new_status, now, now, payload.get("ai_verdict") or "подтверждено", payload.get("ai_score") or 92, comment or "Подтверждено мастером", work_order_id),
        )
    else:
        conn.close(); raise HTTPException(status_code=400, detail="Неизвестное действие")

    conn.commit()
    conn.close()

    ai_result = analyze_work_order(work_order_id)
    conn = get_connection()
    conn.execute(
        "UPDATE work_orders SET ai_verdict = ?, ai_score = ? WHERE id = ?",
        (ai_result.get("ai_verdict") or "подтверждено", ai_result.get("ai_score") or 0, work_order_id),
    )
    conn.commit()
    conn.close()

    log_event(work_order_id, action, executor_user or "system", reason, comment)
    await notify_clients({"type": "dashboard_update", "role": "master"})
    await notify_clients({"type": "worker_update", "username": executor_user})
    return {"ok": True, "status": new_status, "ai": ai_result}


@app.get("/api/history-summary")
def get_history_summary() -> dict[str, Any]:
    conn = get_connection()
    total_orders = conn.execute("SELECT COUNT(*) FROM work_orders").fetchone()[0]
    top_equipment = conn.execute(
        "SELECT equipment_code, COUNT(*) AS count FROM work_orders GROUP BY equipment_code ORDER BY count DESC LIMIT 10"
    ).fetchall()
    k3_orders = conn.execute("SELECT COUNT(*) FROM work_orders WHERE equipment_code = 'К-3'").fetchone()[0]
    rework_by_worker = conn.execute(
        "SELECT executor_user, COUNT(*) AS count FROM work_orders WHERE (description LIKE '%доработка%' OR description LIKE '%Доработка%' OR description LIKE '%возврат на доработку%' OR description LIKE '%Возврат на доработку%' OR title LIKE '%доработка%' OR title LIKE '%Доработка%') GROUP BY executor_user ORDER BY count DESC LIMIT 5"
    ).fetchall()
    repeated_pump_after_repair = conn.execute(
        "SELECT COUNT(*) FROM work_orders WHERE equipment_code = 'Н-2' AND (description LIKE '%после планового%' OR description LIKE '%После планового%' OR description LIKE '%после планового ремонта%' OR description LIKE '%После планового ремонта%')"
    ).fetchone()[0]
    night_shift_overuse = conn.execute(
        "SELECT COUNT(*) FROM work_orders WHERE executor_user IN ('w09', 'w10', 'w11', 'w12') AND (description LIKE '%ночная%' OR description LIKE '%Ночная%' OR title LIKE '%ночная%' OR title LIKE '%Ночная%')"
    ).fetchone()[0]

    summary = {
        "total_orders": total_orders,
        "top_equipment": [dict(item) for item in top_equipment],
        "k3_orders": k3_orders,
        "rework_by_worker": [dict(item) for item in rework_by_worker],
        "repeated_pump_after_repair": repeated_pump_after_repair,
        "night_shift_overuse": night_shift_overuse,
        "signals": {
            "k3_more_than_others": k3_orders > 0,
            "worker_rework_pattern": bool(rework_by_worker),
            "pump_after_repair_pattern": repeated_pump_after_repair > 0,
            "night_shift_pattern": night_shift_overuse > 0,
        },
    }
    conn.close()
    return summary


@app.get("/static/{path:path}")
def static_file(path: str) -> FileResponse:
    return FileResponse(BASE_DIR / "static" / path)


@app.get("/manifest.json")
def manifest() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "manifest.json")


@app.get("/sw.js")
def service_worker() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "sw.js")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True, ws="websockets-sansio")
