"""
Engineering Faculty Biometric Attendance & 70% Exam Eligibility System
Production Backend API (Python FastAPI + PostgreSQL / SQLite fallback)
Supports 300L, 400L, and 500L Departmental Core Courses across all 13 Engineering Departments,
First & Second Semester filtering, Course Deletion, HOD Profile Customization, and JWT Role Security.
"""
import os
import json
import math
import hashlib
import secrets
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any

import jwt
from fastapi import FastAPI, APIRouter, HTTPException, Depends, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Boolean,
    DateTime, ForeignKey, Text, UniqueConstraint, text
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from dotenv import load_dotenv

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET", "eng-biometric-attendance-prod-secret-2026")
JWT_ALGORITHM = "HS256"

# Database Setup: Uses Supabase PostgreSQL in production if DATABASE_URL is reachable,
# with automatic resilient fallback to serverless SQLite (/tmp/eng_attendance_v2.db)
RAW_DB_URL = os.getenv("DATABASE_URL", "").strip()
if RAW_DB_URL.startswith("postgres://"):
    RAW_DB_URL = RAW_DB_URL.replace("postgres://", "postgresql://", 1)

ACTIVE_DB_LABEL = "SQLite (Serverless/Local)"
engine = None

if RAW_DB_URL:
    try:
        test_engine = create_engine(
            RAW_DB_URL,
            pool_pre_ping=True,
            pool_recycle=300,
            connect_args={"connect_timeout": 4},
        )
        with test_engine.connect() as conn:
            pass
        engine = test_engine
        DATABASE_URL = RAW_DB_URL
        ACTIVE_DB_LABEL = "PostgreSQL (Supabase Production)"
    except Exception as db_err:
        print(f"Supabase direct connection notice ({db_err}); using resilient fallback.")

if engine is None:
    db_path = "/tmp/eng_attendance_v2.db" if os.name != "nt" else "./eng_attendance_v2.db"
    DATABASE_URL = f"sqlite:///{db_path}"
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# =====================================================================
# DATABASE MODELS
# =====================================================================

class Department(Base):
    __tablename__ = "departments"
    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(20), unique=True, index=True, nullable=False)  # PEE, CHE, CVE, CPE, EEE, MEE, PRE, STE, AGE, MME, MCE, INE, MRE
    name = Column(String(120), unique=True, nullable=False)
    hod_name = Column(String(120), nullable=False)
    hod_email = Column(String(120), nullable=True)
    hod_pin_hash = Column(String(128), nullable=False)
    min_attendance_pct = Column(Float, default=70.0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Course(Base):
    __tablename__ = "courses"
    id = Column(Integer, primary_key=True, index=True)
    department_id = Column(Integer, ForeignKey("departments.id"), nullable=False, index=True)
    course_code = Column(String(20), index=True, nullable=False)        # e.g., PEE 401
    course_title = Column(String(200), nullable=False)
    level = Column(Integer, nullable=False, index=True)                 # 300, 400, or 500
    semester = Column(Integer, default=1, nullable=False, index=True)   # 1 = First Semester, 2 = Second Semester
    credit_units = Column(Integer, default=3)
    lecturer_name = Column(String(120), nullable=False)
    lecturer_staff_id = Column(String(50), nullable=False)
    lecturer_pin_hash = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class CourseRep(Base):
    __tablename__ = "course_reps"
    id = Column(Integer, primary_key=True, index=True)
    department_id = Column(Integer, ForeignKey("departments.id"), nullable=False, index=True)
    level = Column(Integer, nullable=False, index=True)                 # 300, 400, or 500
    full_name = Column(String(120), nullable=False)
    matric_no = Column(String(64), unique=True, nullable=False)
    pin_hash = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Student(Base):
    __tablename__ = "students"
    id = Column(Integer, primary_key=True, index=True)
    department_id = Column(Integer, ForeignKey("departments.id"), nullable=False, index=True)
    level = Column(Integer, nullable=False, index=True)                 # 300, 400, or 500
    matric_no = Column(String(64), unique=True, index=True, nullable=False)  # Flexible: ENG/123/4567, UB6474386, B1222329, PG2307676
    full_name = Column(String(120), nullable=False)
    email = Column(String(150), nullable=False)                         # Institutional email for HOD warning alerts
    face_descriptor_json = Column(Text, nullable=True)
    webauthn_credential_id = Column(String(255), nullable=True)
    biometric_enrolled_at = Column(DateTime, nullable=True)
    enrolled_by_rep = Column(String(120), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class LectureSession(Base):
    __tablename__ = "lecture_sessions"
    id = Column(Integer, primary_key=True, index=True)
    session_uid = Column(String(64), unique=True, index=True, nullable=False)
    course_id = Column(Integer, ForeignKey("courses.id"), nullable=False, index=True)
    department_id = Column(Integer, ForeignKey("departments.id"), nullable=False, index=True)
    level = Column(Integer, nullable=False, index=True)
    semester = Column(Integer, default=1, nullable=False, index=True)   # 1 = First Semester, 2 = Second Semester
    topic = Column(String(200), nullable=False)
    week_number = Column(Integer, default=1)
    started_by = Column(String(120), nullable=False)
    status = Column(String(20), default="ACTIVE")                       # ACTIVE, CLOSED
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    session_secret = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    closed_at = Column(DateTime, nullable=True)


class AttendanceRecord(Base):
    __tablename__ = "attendance_records"
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("lecture_sessions.id"), nullable=False, index=True)
    course_id = Column(Integer, ForeignKey("courses.id"), nullable=False, index=True)
    student_id = Column(Integer, ForeignKey("students.id"), nullable=False, index=True)
    matric_no = Column(String(64), nullable=False, index=True)
    verification_method = Column(String(50), nullable=False)            # FACE_BIOMETRIC_KIOSK, DEVICE_FINGERPRINT_PASSKEY
    confidence_score = Column(Float, default=0.98)
    captured_offline = Column(Boolean, default=False)
    client_timestamp = Column(String(64), nullable=True)
    synced_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("session_id", "student_id", name="uq_session_student_attendance"),
    )


# =====================================================================
# HELPERS, MIGRATIONS & SEED DATA FOR ALL 13 ENGINEERING DEPARTMENTS
# =====================================================================

ALL_13_ENGINEERING_DEPARTMENTS = [
    ("PEE", "Petroleum Engineering", "Prof. E. O. Adewale"),
    ("CHE", "Chemical Engineering", "Prof. S. U. Eze"),
    ("CVE", "Civil Engineering", "Prof. T. K. Danjuma"),
    ("CPE", "Computer Engineering", "Dr. A. M. Nsofor"),
    ("EEE", "Electrical/Electronic Engineering", "Prof. I. A. Bello"),
    ("MEE", "Mechanical Engineering", "Prof. C. N. Okafor"),
    ("PRE", "Production Engineering", "Prof. O. A. Ibhadode"),
    ("STE", "Structural Engineering", "Prof. K. O. Olusola"),
    ("AGE", "Agricultural Engineering", "Prof. A. O. Olatunji"),
    ("MME", "Metallurgical and Materials Engineering", "Prof. M. N. Nebo"),
    ("MCE", "Mechatronics Engineering", "Prof. S. A. Lawal"),
    ("INE", "Industrial Engineering", "Prof. B. O. Akinnuli"),
    ("MRE", "Marine Engineering", "Prof. D. T. Tamuno"),
]


def hash_pin(pin: str) -> str:
    return hashlib.sha256(f"eng_salt_2026:{pin.strip()}".encode()).hexdigest()


def create_access_token(data: Dict[str, Any]) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(hours=18)
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_access_token(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Authentication required: Please unlock this portal with your Role PIN/Credentials first."
        )
    token = authorization.split(" ", 1)[1].strip()
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Session expired or invalid security token. Please sign in to the portal again."
        )


def compute_cosine_similarity(vec_a: List[float], vec_b: List[float]) -> float:
    if not vec_a or not vec_b or len(vec_a) != len(vec_b):
        return 0.0
    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    norm_a = math.sqrt(sum(a * a for a in vec_a))
    norm_b = math.sqrt(sum(b * b for b in vec_b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def generate_deterministic_signature(seed_text: str, dims: int = 32) -> List[float]:
    vals = []
    for i in range(dims):
        h = hashlib.sha256(f"{seed_text}:{i}".encode()).digest()
        val = (int.from_bytes(h[:4], "big") / 0xFFFFFFFF) * 2.0 - 1.0
        vals.append(round(val, 5))
    norm = math.sqrt(sum(v * v for v in vals)) or 1.0
    return [round(v / norm, 5) for v in vals]


def normalize_course_code(code: str) -> str:
    """Formats course codes consistently (e.g. 'pee571' or 'PEE  571' -> 'PEE 571')."""
    import re
    raw = re.sub(r"\s+", "", code.strip().upper())
    m = re.match(r"^([A-Z]{2,4})(\d{3}[A-Z]?)$", raw)
    if m:
        return f"{m.group(1)} {m.group(2)}"
    return re.sub(r"\s+", " ", code.strip().upper())


def parse_assigned_lecturers(lecturer_field: str) -> List[str]:
    """
    Splits a course's lecturer_name field into individual assigned co-lecturers.
    Supports formats like: 'Prof. Oyeneyin & Engr. Omoregbe', 'Prof. Oyeneyin, Engr. Omoregbe',
    'Prof. Oyeneyin / Engr. Omoregbe', or 'Prof. Oyeneyin and Engr. Omoregbe'.
    """
    import re
    if not lecturer_field:
        return ["Course Lecturer"]
    parts = re.split(r"\s*(?:,|&|/|;|\band\b)\s*", lecturer_field.strip(), flags=re.IGNORECASE)
    cleaned = [p.strip() for p in parts if p and p.strip()]
    return cleaned if cleaned else [lecturer_field.strip()]


def deduplicate_courses_in_db(db: Session):
    """Merges any duplicate courses (like multiple PEE 571 entries) and keeps only 1 clean record."""
    all_courses = db.query(Course).order_by(Course.id.asc()).all()
    seen = {}
    removed_any = False
    for c in all_courses:
        norm_code = normalize_course_code(c.course_code)
        if c.course_code != norm_code:
            c.course_code = norm_code
            removed_any = True
        key = (c.department_id, norm_code)
        if key in seen:
            primary = seen[key]
            # Reassign any lecture sessions or attendance records to the primary course before deleting duplicate
            db.query(LectureSession).filter(LectureSession.course_id == c.id).update({"course_id": primary.id})
            db.query(AttendanceRecord).filter(AttendanceRecord.course_id == c.id).update({"course_id": primary.id})
            db.delete(c)
            removed_any = True
        else:
            seen[key] = c
    if removed_any:
        db.commit()


def run_schema_migrations():
    """Safely adds `semester` columns to existing Supabase PostgreSQL tables and cleans up PEE310."""
    with engine.begin() as conn:
        try:
            conn.execute(text("ALTER TABLE courses ADD COLUMN IF NOT EXISTS semester INTEGER DEFAULT 1 NOT NULL"))
        except Exception:
            try:
                conn.execute(text("ALTER TABLE courses ADD COLUMN semester INTEGER DEFAULT 1 NOT NULL"))
            except Exception:
                pass
        try:
            conn.execute(text("ALTER TABLE lecture_sessions ADD COLUMN IF NOT EXISTS semester INTEGER DEFAULT 1 NOT NULL"))
        except Exception:
            try:
                conn.execute(text("ALTER TABLE lecture_sessions ADD COLUMN semester INTEGER DEFAULT 1 NOT NULL"))
            except Exception:
                pass


def init_and_seed_db():
    Base.metadata.create_all(bind=engine)
    run_schema_migrations()
    db = SessionLocal()
    try:
        # Remove PEE310 / PEE 310 as explicitly requested by the user
        pee310_courses = db.query(Course).filter(
            Course.course_code.in_(["PEE310", "PEE 310", "PET310", "PET 310"])
        ).all()
        for c_del in pee310_courses:
            db.query(AttendanceRecord).filter(AttendanceRecord.course_id == c_del.id).delete()
            db.query(LectureSession).filter(LectureSession.course_id == c_del.id).delete()
            db.delete(c_del)
        if pee310_courses:
            db.commit()

        # Deduplicate any duplicate courses (such as multiple PEE 571 entries)
        deduplicate_courses_in_db(db)

        # Migrate legacy PET code to PEE if present, and ensure all 13 departments exist
        legacy_pet = db.query(Department).filter(Department.code == "PET").first()
        if legacy_pet:
            legacy_pet.code = "PEE"
            legacy_pet.name = "Petroleum Engineering"
            db.commit()

        dept_map = {}
        for code, name, hod in ALL_13_ENGINEERING_DEPARTMENTS:
            existing = db.query(Department).filter(Department.code == code).first()
            if not existing:
                existing = Department(
                    code=code,
                    name=name,
                    hod_name=hod,
                    hod_email=f"hod.{code.lower()}@eng.edu.ng",
                    hod_pin_hash=hash_pin("1234"),
                    min_attendance_pct=70.0,
                )
                db.add(existing)
                db.flush()
            dept_map[code] = existing

        #Also ensure any existing courses with PET prefix are updated to PEE
        pet_courses = db.query(Course).filter(Course.course_code.like("PET %")).all()
        for pc in pet_courses:
            pc.course_code = pc.course_code.replace("PET ", "PEE ", 1)
        db.commit()

        # Ensure Second Semester demo courses exist for PEE so both 1st & 2nd Semester views have rich courses
        pee_dept = dept_map.get("PEE")
        if pee_dept:
            # Update PEE 401 to feature co-teaching by Prof. Oyeneyin & Engr. Omoregbe if still on default demo name
            pee401 = db.query(Course).filter(
                Course.department_id == pee_dept.id,
                Course.course_code == "PEE 401"
            ).first()
            if pee401 and pee401.lecturer_name == "Dr. M. O. Nwosu":
                pee401.lecturer_name = "Prof. Oyeneyin & Engr. Omoregbe"
                db.commit()

            second_sem_pee = [
                ("PEE 302", "Reservoir Rock & Fluid Properties Lab (2nd Sem)", 300, 2, 3, "Dr. K. Ibe", "STF-PEE-07"),
                ("PEE 402", "Natural Gas Transmission & Processing (2nd Sem)", 400, 2, 4, "Prof. Oyeneyin & Engr. Omoregbe", "STF-PEE-08"),
                ("PEE 404", "Subsea & Offshore Drilling Engineering (2nd Sem)", 400, 2, 3, "Prof. E. O. Adewale", "STF-PEE-09"),
                ("PEE 502", "Enhanced Oil Recovery & Reservoir Simulation (2nd Sem)", 500, 2, 4, "Prof. B. Tamuno", "STF-PEE-10"),
            ]
            for c_code, title, lvl, sem, units, lect, staff_id in second_sem_pee:
                exists_c = db.query(Course).filter(
                    Course.department_id == pee_dept.id,
                    Course.course_code == c_code
                ).first()
                if not exists_c:
                    db.add(Course(
                        department_id=pee_dept.id,
                        course_code=c_code,
                        course_title=title,
                        level=lvl,
                        semester=sem,
                        credit_units=units,
                        lecturer_name=lect,
                        lecturer_staff_id=staff_id,
                        lecturer_pin_hash=hash_pin("1234"),
                    ))
            db.commit()

        if db.query(Course).count() > 6:
            return

        # Seed Departmental Core Courses for 300L, 400L, and 500L across key departments
        courses_seed = [
            # Petroleum Engineering (PEE) - 1st Semester
            ("PEE", "PEE 301", "Reservoir Engineering I", 300, 1, 3, "Dr. K. Ibe", "STF-PEE-01"),
            ("PEE", "PEE 303", "Drilling Fluids Technology", 300, 1, 3, "Engr. Dr. F. Briggs", "STF-PEE-02"),
            ("PEE", "PEE 401", "Applied Reservoir Engineering II", 400, 1, 4, "Dr. M. O. Nwosu", "STF-PEE-03"),
            ("PEE", "PEE 403", "Well Logging & Formation Evaluation", 400, 1, 3, "Prof. E. O. Adewale", "STF-PEE-04"),
            ("PEE", "PEE 501", "Petroleum Production Engineering", 500, 1, 4, "Prof. B. Tamuno", "STF-PEE-05"),
            ("PEE", "PEE 505", "Natural Gas Engineering & Processing", 500, 1, 3, "Dr. R. Lawson", "STF-PEE-06"),
            # Chemical Engineering (CHE)
            ("CHE", "CHE 301", "Chemical Engineering Thermodynamics", 300, 1, 3, "Dr. U. Okafor", "STF-CHE-01"),
            ("CHE", "CHE 401", "Chemical Reaction Kinetics & Reactor Design", 400, 1, 4, "Prof. S. U. Eze", "STF-CHE-02"),
            ("CHE", "CHE 501", "Process Dynamics, Control & Plant Design", 500, 1, 4, "Dr. L. Nwachukwu", "STF-CHE-03"),
            # Civil Engineering (CVE)
            ("CVE", "CVE 301", "Structural Mechanics & Analysis I", 300, 1, 3, "Dr. P. Audu", "STF-CVE-01"),
            ("CVE", "CVE 401", "Design of Reinforced Concrete Structures", 400, 1, 4, "Prof. T. K. Danjuma", "STF-CVE-02"),
            ("CVE", "CVE 501", "Geotechnical & Highway Foundation Engineering", 500, 1, 4, "Dr. G. Osho", "STF-CVE-03"),
            # Computer Engineering (CPE)
            ("CPE", "CPE 301", "Microprocessors & Embedded Systems", 300, 1, 3, "Engr. T. Obi", "STF-CPE-01"),
            ("CPE", "CPE 401", "Computer Architecture & Digital System Design", 400, 1, 4, "Dr. A. M. Nsofor", "STF-CPE-02"),
            ("CPE", "CPE 501", "Distributed Computing & Cyber-Physical Systems", 500, 1, 4, "Prof. V. Okeke", "STF-CPE-03"),
            # Electrical/Electronic Engineering (EEE)
            ("EEE", "EEE 301", "Electromagnetic Fields & Waves", 300, 1, 3, "Dr. J. Kalu", "STF-EEE-01"),
            ("EEE", "EEE 401", "Control Engineering & Instrumentation", 400, 1, 4, "Prof. I. A. Bello", "STF-EEE-02"),
            ("EEE", "EEE 501", "Power Systems Analysis & High Voltage", 500, 1, 4, "Dr. O. Fasanya", "STF-EEE-03"),
            # Mechanical Engineering (MEE)
            ("MEE", "MEE 301", "Fluid Mechanics II", 300, 1, 3, "Dr. A. Balogun", "STF-MEE-01"),
            ("MEE", "MEE 401", "Applied Thermodynamics & Heat Transfer", 400, 1, 4, "Prof. C. N. Okafor", "STF-MEE-02"),
            ("MEE", "MEE 501", "Tribology & Power Plant Engineering", 500, 1, 4, "Dr. H. Usman", "STF-MEE-03"),
            # Production, Structural, Agricultural, Metallurgical, Mechatronics, Industrial, Marine
            ("PRE", "PRE 401", "Manufacturing Technology & Machine Tools", 400, 1, 3, "Prof. O. A. Ibhadode", "STF-PRE-01"),
            ("STE", "STE 401", "Advanced Matrix & Finite Element Structural Analysis", 400, 1, 4, "Prof. K. O. Olusola", "STF-STE-01"),
            ("AGE", "AGE 401", "Irrigation, Drainage & Soil Water Engineering", 400, 1, 3, "Prof. A. O. Olatunji", "STF-AGE-01"),
            ("MME", "MME 401", "Physical Metallurgy & Phase Transformations", 400, 1, 3, "Prof. M. N. Nebo", "STF-MME-01"),
            ("MCE", "MCE 401", "Robotics, Actuators & Mechatronic System Design", 400, 1, 4, "Prof. S. A. Lawal", "STF-MCE-01"),
            ("INE", "INE 401", "Operations Research & Ergonomics", 400, 1, 3, "Prof. B. O. Akinnuli", "STF-INE-01"),
            ("MRE", "MRE 401", "Marine Propulsion Systems & Naval Architecture", 400, 1, 4, "Prof. D. T. Tamuno", "STF-MRE-01"),
        ]

        course_objs = {}
        for d_code, c_code, title, lvl, sem, units, lect, staff_id in courses_seed:
            c = Course(
                department_id=dept_map[d_code].id,
                course_code=c_code,
                course_title=title,
                level=lvl,
                semester=sem,
                credit_units=units,
                lecturer_name=lect,
                lecturer_staff_id=staff_id,
                lecturer_pin_hash=hash_pin("1234"),
            )
            db.add(c)
            db.flush()
            course_objs[c_code] = c

        db.commit()
    except Exception as e:
        db.rollback()
        print(f"Seed warning: {e}")
    finally:
        db.close()


init_and_seed_db()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# =====================================================================
# FASTAPI APPLICATION & SCHEMAS
# =====================================================================

app = FastAPI(
    title="EngAttend Biometric API (300L-500L)",
    description="Zero-Impersonation Biometric Attendance & HOD 70% Exam Eligibility System for Engineering",
    version="1.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AuthLoginRequest(BaseModel):
    role: str = Field(..., description="hod, lecturer, courserep, or student")
    department_id: int
    pin: Optional[str] = None
    matric_no: Optional[str] = None
    level: Optional[int] = 400
    course_id: Optional[int] = Field(default=None, description="Assigned course ID when role=='lecturer'")
    lecturer_name: Optional[str] = Field(default=None, description="Specific co-lecturer signing in for the course")


class DepartmentCreate(BaseModel):
    code: str = Field(..., example="PEE")
    name: str = Field(..., example="Petroleum Engineering")
    hod_name: str = Field(..., example="Prof. E. O. Adewale")
    hod_email: Optional[str] = None
    hod_pin: str = Field(default="1234")


class DepartmentHodUpdate(BaseModel):
    hod_name: str
    hod_email: Optional[str] = None
    new_pin: Optional[str] = None


class CourseCreate(BaseModel):
    department_id: int
    course_code: str = Field(..., example="PEE 405")
    course_title: str = Field(..., example="Drilling Engineering II")
    level: int = Field(..., description="Must be 300, 400, or 500")
    semester: int = Field(default=1, description="1 = First Semester, 2 = Second Semester")
    credit_units: int = Field(default=3)
    lecturer_name: str
    lecturer_staff_id: Optional[str] = None
    lecturer_pin: str = Field(default="1234")


class CourseUpdate(BaseModel):
    """Allows the HOD to edit the exact details that were inputted when adding the course."""
    course_code: str
    course_title: str
    level: int
    semester: int = 1
    lecturer_name: str
    credit_units: Optional[int] = 3
    lecturer_pin: Optional[str] = None


class CourseLecturerPinUpdate(BaseModel):
    """Allows the assigned Course Lecturer(s) or HOD to customize the private PIN for their isolated course."""
    new_pin: str
    lecturer_name: Optional[str] = None


class StudentEnrollRequest(BaseModel):
    department_id: int
    level: int = Field(..., description="300, 400, or 500")
    matric_no: str = Field(..., description="Flexible format: ENG/123/4567, UB6474386, B1222329, PG2307676, etc.")
    full_name: str
    email: str = Field(..., description="Institutional email required for HOD attendance warnings")
    face_descriptor: Optional[List[float]] = None
    webauthn_credential_id: Optional[str] = None
    enrolled_by_rep: str = "Course Rep"


class SessionCreateRequest(BaseModel):
    course_id: int
    topic: str
    week_number: int = 1
    started_by: str
    pin: str = "1234"
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class BiometricCheckInRequest(BaseModel):
    session_uid: str
    matric_no: str
    verification_method: str = "FACE_BIOMETRIC_KIOSK"
    face_descriptor: Optional[List[float]] = None
    webauthn_credential_id: Optional[str] = None
    captured_offline: bool = False
    client_timestamp: Optional[str] = None


class OfflineBulkSyncRequest(BaseModel):
    records: List[BiometricCheckInRequest]


# =====================================================================
# API ENDPOINTS
# =====================================================================

router = APIRouter()


@router.get("/health")
@router.get("/api/health")
def health_check(db: Session = Depends(get_db)):
    return {
        "status": "ok",
        "database_engine": ACTIVE_DB_LABEL,
        "supported_levels": [300, 400, 500],
        "supported_semesters": [1, 2],
        "departments_count": db.query(Department).count(),
        "courses_count": db.query(Course).count(),
        "students_count": db.query(Student).count(),
    }


@router.post("/auth/login")
@router.post("/api/auth/login")
def role_portal_login(payload: AuthLoginRequest, db: Session = Depends(get_db)):
    """
    Authenticates access to the 4 protected role portals:
    1. HOD Portal (Department HOD PIN)
    2. Course Lecturer Portal (Lecturer Staff PIN)
    3. Level Course Rep Portal (Course Rep PIN + Matric No)
    4. Student Profile Portal (Student Matric No verification)
    """
    role = payload.role.strip().lower()
    dept = db.query(Department).filter(Department.id == payload.department_id).first()
    if not dept:
        raise HTTPException(status_code=404, detail="Department not found.")

    if role == "hod":
        if not payload.pin:
            raise HTTPException(status_code=400, detail="Enter the Department HOD Security PIN.")
        if hash_pin(payload.pin) != dept.hod_pin_hash:
            raise HTTPException(status_code=401, detail="Invalid HOD PIN for this department.")
        token = create_access_token({
            "role": "hod",
            "department_id": dept.id,
            "department_code": dept.code,
            "actor_name": dept.hod_name,
        })
        return {
            "message": f"Welcome, {dept.hod_name} (HOD, {dept.code})",
            "token": token,
            "role": "hod",
            "department_id": dept.id,
            "actor_name": dept.hod_name,
        }

    elif role == "lecturer":
        if not payload.pin:
            raise HTTPException(status_code=400, detail="Enter your Course Lecturer Access PIN.")
        if not payload.course_id:
            raise HTTPException(status_code=400, detail="Select your assigned course to unlock your isolated Course Lecturer workspace.")

        matched_course = db.query(Course).filter(
            Course.id == payload.course_id,
            Course.department_id == dept.id,
        ).first()
        if not matched_course:
            raise HTTPException(status_code=404, detail="Selected course was not found in this department.")

        pin_h = hash_pin(payload.pin)
        if pin_h != matched_course.lecturer_pin_hash:
            raise HTTPException(
                status_code=401,
                detail=f"Invalid Lecturer PIN for {matched_course.course_code}. Only lecturers assigned to {matched_course.course_code} can access its database."
            )

        assigned_list = parse_assigned_lecturers(matched_course.lecturer_name)
        chosen_lecturer = (payload.lecturer_name or "").strip()
        if not chosen_lecturer or chosen_lecturer not in assigned_list:
            chosen_lecturer = assigned_list[0]

        actor = f"{chosen_lecturer} ({matched_course.course_code})"
        token = create_access_token({
            "role": "lecturer",
            "department_id": dept.id,
            "department_code": dept.code,
            "course_id": matched_course.id,
            "course_code": matched_course.course_code,
            "lecturer_name": chosen_lecturer,
            "actor_name": actor,
        })
        return {
            "message": f"Isolated Course Workspace Unlocked: {matched_course.course_code} — {chosen_lecturer}",
            "token": token,
            "role": "lecturer",
            "department_id": dept.id,
            "course_id": matched_course.id,
            "course_code": matched_course.course_code,
            "course_title": matched_course.course_title,
            "level": matched_course.level,
            "semester": matched_course.semester or 1,
            "lecturer_name": chosen_lecturer,
            "assigned_lecturers": assigned_list,
            "actor_name": actor,
        }

    elif role == "courserep":
        if not payload.pin:
            raise HTTPException(status_code=400, detail="Enter the Level Course Rep PIN.")
        pin_h = hash_pin(payload.pin)
        rep = db.query(CourseRep).filter(
            CourseRep.department_id == dept.id,
            CourseRep.pin_hash == pin_h
        ).first()
        if not rep and pin_h != hash_pin("1234"):
            raise HTTPException(status_code=401, detail="Invalid Level Course Rep PIN.")
        actor = rep.full_name if rep else f"{payload.level or 400}L Course Rep ({dept.code})"
        token = create_access_token({
            "role": "courserep",
            "department_id": dept.id,
            "department_code": dept.code,
            "level": payload.level or 400,
            "actor_name": actor,
        })
        return {
            "message": f"Course Rep Kiosk Unlocked: {actor}",
            "token": token,
            "role": "courserep",
            "department_id": dept.id,
            "actor_name": actor,
        }

    elif role == "student":
        if not payload.matric_no:
            raise HTTPException(status_code=400, detail="Enter your Matriculation Number to unlock your Student Portal.")
        matric = payload.matric_no.strip().upper()
        st = db.query(Student).filter(Student.matric_no == matric).first()
        if not st:
            raise HTTPException(
                status_code=404,
                detail=f"Matric No '{matric}' is not enrolled yet. Please meet your Level Course Rep to enroll your biometrics."
            )
        token = create_access_token({
            "role": "student",
            "department_id": st.department_id,
            "student_id": st.id,
            "matric_no": st.matric_no,
            "actor_name": st.full_name,
        })
        return {
            "message": f"Welcome, {st.full_name} ({st.matric_no})",
            "token": token,
            "role": "student",
            "department_id": st.department_id,
            "matric_no": st.matric_no,
            "actor_name": st.full_name,
        }

    raise HTTPException(status_code=400, detail="Invalid role specified.")


@router.get("/departments")
@router.get("/api/departments")
def list_departments(db: Session = Depends(get_db)):
    depts = db.query(Department).order_by(Department.id).all()
    result = []
    for d in depts:
        courses_count = db.query(Course).filter(Course.department_id == d.id).count()
        students_count = db.query(Student).filter(Student.department_id == d.id).count()
        result.append({
            "id": d.id,
            "code": d.code,
            "name": d.name,
            "hod_name": d.hod_name,
            "hod_email": d.hod_email,
            "min_attendance_pct": d.min_attendance_pct,
            "courses_count": courses_count,
            "students_count": students_count,
        })
    return result


@router.post("/departments")
@router.post("/api/departments")
def register_department(
    payload: DepartmentCreate,
    claims: Dict[str, Any] = Depends(verify_access_token),
    db: Session = Depends(get_db)
):
    if claims.get("role") != "hod":
        raise HTTPException(status_code=403, detail="Only an authenticated HOD can register a department.")
    code = payload.code.strip().upper()
    existing = db.query(Department).filter(Department.code == code).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Department {code} is already registered.")
    dept = Department(
        code=code,
        name=payload.name.strip(),
        hod_name=payload.hod_name.strip(),
        hod_email=payload.hod_email,
        hod_pin_hash=hash_pin(payload.hod_pin),
        min_attendance_pct=70.0,
    )
    db.add(dept)
    db.commit()
    db.refresh(dept)
    return {"message": f"Department of {dept.name} ({dept.code}) registered successfully.", "department": {
        "id": dept.id, "code": dept.code, "name": dept.name, "hod_name": dept.hod_name
    }}


@router.put("/departments/{department_id}/hod")
@router.put("/api/departments/{department_id}/hod")
def update_department_hod_profile(
    department_id: int,
    payload: DepartmentHodUpdate,
    claims: Dict[str, Any] = Depends(verify_access_token),
    db: Session = Depends(get_db),
):
    """Allows the HOD to replace the default/demo HOD name, email, and security PIN for their department."""
    if claims.get("role") != "hod":
        raise HTTPException(status_code=403, detail="Only an authenticated HOD can update HOD profile & security settings.")
    dept = db.query(Department).filter(Department.id == department_id).first()
    if not dept:
        raise HTTPException(status_code=404, detail="Department not found.")
    dept.hod_name = payload.hod_name.strip()
    if payload.hod_email is not None:
        dept.hod_email = payload.hod_email.strip()
    if payload.new_pin and len(payload.new_pin.strip()) >= 4:
        dept.hod_pin_hash = hash_pin(payload.new_pin.strip())
    db.commit()
    db.refresh(dept)
    return {
        "message": f"Updated HOD profile & security settings for {dept.name} ({dept.code}).",
        "department": {
            "id": dept.id,
            "code": dept.code,
            "name": dept.name,
            "hod_name": dept.hod_name,
            "hod_email": dept.hod_email,
        }
    }


@router.get("/courses")
@router.get("/api/courses")
def list_courses(
    department_id: Optional[int] = Query(None),
    level: Optional[int] = Query(None),
    semester: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(Course)
    if department_id:
        q = q.filter(Course.department_id == department_id)
    if level:
        q = q.filter(Course.level == level)
    if semester in (1, 2):
        q = q.filter(Course.semester == semester)
    courses = q.order_by(Course.level, Course.semester, Course.course_code).all()
    out = []
    for c in courses:
        total_sessions = db.query(LectureSession).filter(LectureSession.course_id == c.id).count()
        active_sess = db.query(LectureSession).filter(
            LectureSession.course_id == c.id, LectureSession.status == "ACTIVE"
        ).first()
        out.append({
            "id": c.id,
            "department_id": c.department_id,
            "course_code": c.course_code,
            "course_title": c.course_title,
            "level": c.level,
            "semester": c.semester or 1,
            "credit_units": c.credit_units,
            "lecturer_name": c.lecturer_name,
            "assigned_lecturers": parse_assigned_lecturers(c.lecturer_name),
            "lecturer_staff_id": c.lecturer_staff_id,
            "total_sessions": total_sessions,
            "active_session_uid": active_sess.session_uid if active_sess else None,
        })
    return out


@router.post("/courses")
@router.post("/api/courses")
def create_course(
    payload: CourseCreate,
    claims: Dict[str, Any] = Depends(verify_access_token),
    db: Session = Depends(get_db),
):
    if claims.get("role") != "hod":
        raise HTTPException(status_code=403, detail="Only an authenticated Department HOD can add courses.")
    if payload.level not in (300, 400, 500):
        raise HTTPException(
            status_code=400,
            detail="Only 300L, 400L, and 500L departmental core courses are supported."
        )
    if payload.semester not in (1, 2):
        raise HTTPException(status_code=400, detail="Semester must be 1 (First Semester) or 2 (Second Semester).")

    code_clean = normalize_course_code(payload.course_code)
    existing_course = db.query(Course).filter(
        Course.department_id == payload.department_id,
        Course.course_code == code_clean
    ).first()
    if existing_course:
        sem_label = "First Semester" if existing_course.semester == 1 else "Second Semester"
        return {
            "message": f"Course {existing_course.course_code} ({sem_label}) is already registered.",
            "id": existing_course.id,
            "already_existed": True,
        }

    staff_id = (payload.lecturer_staff_id or f"STF-{code_clean.replace(' ', '')}").strip().upper()
    c = Course(
        department_id=payload.department_id,
        course_code=code_clean,
        course_title=payload.course_title.strip(),
        level=payload.level,
        semester=payload.semester,
        credit_units=payload.credit_units,
        lecturer_name=payload.lecturer_name.strip(),
        lecturer_staff_id=staff_id,
        lecturer_pin_hash=hash_pin(payload.lecturer_pin),
    )
    db.add(c)
    db.commit()
    db.refresh(c)
    sem_label = "First Semester" if c.semester == 1 else "Second Semester"
    return {"message": f"Course {c.course_code} ({sem_label}) added successfully.", "id": c.id}


@router.put("/courses/{course_id}")
@router.put("/api/courses/{course_id}")
def update_course_details(
    course_id: int,
    payload: CourseUpdate,
    claims: Dict[str, Any] = Depends(verify_access_token),
    db: Session = Depends(get_db),
):
    """Allows the HOD to edit the exact details inputted when adding a course (Code, Level, Semester, Title, Lecturer, PIN)."""
    if claims.get("role") != "hod":
        raise HTTPException(status_code=403, detail="Only an authenticated Department HOD can edit course details.")
    course = db.query(Course).filter(Course.id == course_id).first()
    if not course:
        raise HTTPException(status_code=404, detail="Course not found.")
    if payload.level not in (300, 400, 500):
        raise HTTPException(status_code=400, detail="Course level must be 300, 400, or 500.")
    if payload.semester not in (1, 2):
        raise HTTPException(status_code=400, detail="Semester must be 1 (First Semester) or 2 (Second Semester).")

    course.course_code = normalize_course_code(payload.course_code)
    course.course_title = payload.course_title.strip()
    course.level = payload.level
    course.semester = payload.semester
    course.lecturer_name = payload.lecturer_name.strip()
    if payload.credit_units is not None:
        course.credit_units = payload.credit_units
    if payload.lecturer_pin and len(payload.lecturer_pin.strip()) >= 4:
        course.lecturer_pin_hash = hash_pin(payload.lecturer_pin.strip())

    sessions = db.query(LectureSession).filter(LectureSession.course_id == course.id).all()
    for s in sessions:
        s.level = course.level
        s.semester = course.semester

    db.commit()
    db.refresh(course)
    return {
        "message": f"Course {course.course_code} updated successfully.",
        "course": {
            "id": course.id,
            "course_code": course.course_code,
            "course_title": course.course_title,
            "level": course.level,
            "semester": course.semester,
            "lecturer_name": course.lecturer_name,
            "assigned_lecturers": parse_assigned_lecturers(course.lecturer_name),
        }
    }


@router.put("/courses/{course_id}/lecturer-pin")
@router.put("/api/courses/{course_id}/lecturer-pin")
def update_course_lecturer_pin(
    course_id: int,
    payload: CourseLecturerPinUpdate,
    claims: Dict[str, Any] = Depends(verify_access_token),
    db: Session = Depends(get_db),
):
    """
    Allows an authenticated Course Lecturer (for their own assigned course only) or the HOD
    to set a private Course Access PIN so no other lecturer can unlock this course.
    """
    role = claims.get("role")
    if role not in ("lecturer", "hod"):
        raise HTTPException(status_code=403, detail="Only the assigned Course Lecturer or HOD can update this course's PIN.")
    if role == "lecturer" and claims.get("course_id") != course_id:
        raise HTTPException(
            status_code=403,
            detail="Strict Course Isolation: You can only modify the security PIN for your own assigned course."
        )
    course = db.query(Course).filter(Course.id == course_id).first()
    if not course:
        raise HTTPException(status_code=404, detail="Course not found.")
    if not payload.new_pin or len(payload.new_pin.strip()) < 4:
        raise HTTPException(status_code=400, detail="New Course PIN must be at least 4 characters.")

    course.lecturer_pin_hash = hash_pin(payload.new_pin.strip())
    if payload.lecturer_name and payload.lecturer_name.strip():
        course.lecturer_name = payload.lecturer_name.strip()
    db.commit()
    db.refresh(course)
    return {
        "message": f"Updated private Lecturer Access PIN for {course.course_code}. Only {course.lecturer_name} can unlock this course.",
        "course_id": course.id,
        "course_code": course.course_code,
        "lecturer_name": course.lecturer_name,
        "assigned_lecturers": parse_assigned_lecturers(course.lecturer_name),
    }


@router.delete("/courses/{course_id}")
@router.delete("/api/courses/{course_id}")
def delete_course(
    course_id: int,
    claims: Dict[str, Any] = Depends(verify_access_token),
    db: Session = Depends(get_db),
):
    """Allows the HOD to permanently remove a course and its associated sessions."""
    if claims.get("role") != "hod":
        raise HTTPException(status_code=403, detail="Only an authenticated Department HOD can remove courses.")
    course = db.query(Course).filter(Course.id == course_id).first()
    if not course:
        raise HTTPException(status_code=404, detail="Course not found.")
    code = course.course_code
    db.query(AttendanceRecord).filter(AttendanceRecord.course_id == course.id).delete()
    db.query(LectureSession).filter(LectureSession.course_id == course.id).delete()
    db.delete(course)
    db.commit()
    return {"message": f"Course {code} has been permanently removed."}


@router.get("/students")
@router.get("/api/students")
def list_students(
    department_id: Optional[int] = Query(None),
    level: Optional[int] = Query(None),
    include_templates: bool = Query(False),
    db: Session = Depends(get_db),
):
    q = db.query(Student)
    if department_id:
        q = q.filter(Student.department_id == department_id)
    if level:
        q = q.filter(Student.level == level)
    students = q.order_by(Student.matric_no).all()
    result = []
    for s in students:
        item = {
            "id": s.id,
            "department_id": s.department_id,
            "level": s.level,
            "matric_no": s.matric_no,
            "full_name": s.full_name,
            "email": s.email,
            "has_face_biometric": bool(s.face_descriptor_json),
            "has_passkey": bool(s.webauthn_credential_id),
            "biometric_enrolled_at": s.biometric_enrolled_at.isoformat() if s.biometric_enrolled_at else None,
            "enrolled_by_rep": s.enrolled_by_rep,
        }
        if include_templates:
            item["face_descriptor"] = json.loads(s.face_descriptor_json) if s.face_descriptor_json else None
            item["webauthn_credential_id"] = s.webauthn_credential_id
        result.append(item)
    return result


@router.post("/students/enroll")
@router.post("/api/students/enroll")
def enroll_student_biometrics(
    payload: StudentEnrollRequest,
    claims: Dict[str, Any] = Depends(verify_access_token),
    db: Session = Depends(get_db),
):
    if claims.get("role") not in ("courserep", "hod", "lecturer"):
        raise HTTPException(status_code=403, detail="Only an authenticated Course Rep, Lecturer, or HOD can enroll students.")
    if payload.level not in (300, 400, 500):
        raise HTTPException(status_code=400, detail="Student level must be 300, 400, or 500.")

    matric = payload.matric_no.strip().upper()
    if len(matric) < 3:
        raise HTTPException(status_code=400, detail="Please enter a valid Matriculation Number.")

    email_clean = payload.email.strip().lower()
    if not email_clean or "@" not in email_clean:
        raise HTTPException(
            status_code=400,
            detail="A valid Institutional Email is required so the HOD can send attendance warnings."
        )

    student = db.query(Student).filter(Student.matric_no == matric).first()

    face_vec = payload.face_descriptor
    if not face_vec:
        face_vec = generate_deterministic_signature(matric)

    if student:
        student.full_name = payload.full_name.strip()
        student.level = payload.level
        student.department_id = payload.department_id
        student.email = email_clean
        student.face_descriptor_json = json.dumps(face_vec)
        if payload.webauthn_credential_id:
            student.webauthn_credential_id = payload.webauthn_credential_id
        student.biometric_enrolled_at = datetime.now(timezone.utc)
        student.enrolled_by_rep = payload.enrolled_by_rep
    else:
        student = Student(
            department_id=payload.department_id,
            level=payload.level,
            matric_no=matric,
            full_name=payload.full_name.strip(),
            email=email_clean,
            face_descriptor_json=json.dumps(face_vec),
            webauthn_credential_id=payload.webauthn_credential_id or f"passkey-{matric.replace('/', '-')}",
            biometric_enrolled_at=datetime.now(timezone.utc),
            enrolled_by_rep=payload.enrolled_by_rep,
        )
        db.add(student)

    db.commit()
    db.refresh(student)
    return {
        "message": f"Biometrics & Institutional Email enrolled for {student.full_name} ({student.matric_no})",
        "student": {
            "id": student.id,
            "matric_no": student.matric_no,
            "full_name": student.full_name,
            "email": student.email,
            "level": student.level,
            "has_face_biometric": True,
            "face_descriptor": face_vec,
        },
    }


@router.post("/sessions")
@router.post("/api/sessions")
def start_lecture_session(
    payload: SessionCreateRequest,
    claims: Dict[str, Any] = Depends(verify_access_token),
    db: Session = Depends(get_db),
):
    role = claims.get("role")
    if role not in ("lecturer", "hod", "courserep"):
        raise HTTPException(status_code=403, detail="Only an authenticated Course Lecturer, HOD, or Course Rep can start a session.")

    # Strict Course Isolation for Lecturers: can only launch sessions for their own authenticated course
    if role == "lecturer" and claims.get("course_id") and claims.get("course_id") != payload.course_id:
        raise HTTPException(
            status_code=403,
            detail=f"Strict Course Isolation: You are signed in to {claims.get('course_code')}. You cannot launch or modify sessions for another lecturer's course."
        )

    course = db.query(Course).filter(Course.id == payload.course_id).first()
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    assigned_list = parse_assigned_lecturers(course.lecturer_name)
    requested_lecturer = (payload.started_by or claims.get("lecturer_name") or "").strip()
    if not requested_lecturer:
        requested_lecturer = assigned_list[0]

    uid = f"SESS-{course.course_code.replace(' ', '')}-W{payload.week_number}-{secrets.token_hex(3).upper()}"
    sess = LectureSession(
        session_uid=uid,
        course_id=course.id,
        department_id=course.department_id,
        level=course.level,
        semester=course.semester or 1,
        topic=payload.topic.strip(),
        week_number=payload.week_number,
        started_by=requested_lecturer,
        status="ACTIVE",
        latitude=payload.latitude,
        longitude=payload.longitude,
        session_secret=secrets.token_hex(8),
    )
    db.add(sess)
    db.commit()
    db.refresh(sess)
    return {
        "message": f"Live session launched for {course.course_code} — Taught by {sess.started_by}",
        "session": {
            "id": sess.id,
            "session_uid": sess.session_uid,
            "course_id": course.id,
            "course_code": course.course_code,
            "course_title": course.course_title,
            "level": course.level,
            "semester": sess.semester,
            "topic": sess.topic,
            "week_number": sess.week_number,
            "started_by": sess.started_by,
            "status": sess.status,
            "created_at": sess.created_at.isoformat(),
        },
    }


@router.get("/sessions")
@router.get("/api/sessions")
def list_sessions(
    department_id: Optional[int] = Query(None),
    course_id: Optional[int] = Query(None),
    level: Optional[int] = Query(None),
    semester: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(LectureSession)
    if department_id:
        q = q.filter(LectureSession.department_id == department_id)
    if course_id:
        q = q.filter(LectureSession.course_id == course_id)
    if level:
        q = q.filter(LectureSession.level == level)
    if semester in (1, 2):
        q = q.filter(LectureSession.semester == semester)
    sessions = q.order_by(LectureSession.id.desc()).limit(50).all()

    out = []
    for s in sessions:
        course = db.query(Course).filter(Course.id == s.course_id).first()
        present_count = db.query(AttendanceRecord).filter(AttendanceRecord.session_id == s.id).count()
        total_level_students = db.query(Student).filter(
            Student.department_id == s.department_id, Student.level == s.level
        ).count()
        out.append({
            "id": s.id,
            "session_uid": s.session_uid,
            "course_id": s.course_id,
            "course_code": course.course_code if course else "N/A",
            "course_title": course.course_title if course else "N/A",
            "level": s.level,
            "semester": s.semester or (course.semester if course else 1),
            "topic": s.topic,
            "week_number": s.week_number,
            "started_by": s.started_by,
            "status": s.status,
            "present_count": present_count,
            "total_class_size": total_level_students,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        })
    return out


@router.post("/sessions/{session_uid}/close")
@router.post("/api/sessions/{session_uid}/close")
def close_session(
    session_uid: str,
    claims: Dict[str, Any] = Depends(verify_access_token),
    db: Session = Depends(get_db),
):
    role = claims.get("role")
    if role not in ("lecturer", "hod"):
        raise HTTPException(status_code=403, detail="Only an authenticated Course Lecturer or HOD can lock a session.")
    sess = db.query(LectureSession).filter(LectureSession.session_uid == session_uid).first()
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")

    if role == "lecturer" and claims.get("course_id") and claims.get("course_id") != sess.course_id:
        raise HTTPException(
            status_code=403,
            detail="Strict Course Isolation: You cannot lock or modify a session belonging to another course."
        )

    sess.status = "CLOSED"
    sess.closed_at = datetime.now(timezone.utc)
    db.commit()
    return {"message": f"Session {session_uid} (Taught by {sess.started_by}) closed and locked for HOD reporting."}


def _process_single_checkin(item: BiometricCheckInRequest, db: Session, allowed_course_id: Optional[int] = None) -> Dict[str, Any]:
    sess = db.query(LectureSession).filter(LectureSession.session_uid == item.session_uid).first()
    if not sess:
        raise HTTPException(status_code=404, detail=f"Session {item.session_uid} not found.")

    if allowed_course_id is not None and sess.course_id != allowed_course_id:
        raise HTTPException(
            status_code=403,
            detail="Strict Course Isolation: You can only record or sync attendance for your own assigned course."
        )

    matric = item.matric_no.strip().upper()
    student = db.query(Student).filter(Student.matric_no == matric).first()
    if not student:
        raise HTTPException(status_code=404, detail=f"Student {matric} not found in registry.")

    if student.department_id != sess.department_id or student.level != sess.level:
        raise HTTPException(
            status_code=403,
            detail=f"Level/Department mismatch: {matric} is {student.level}L, session is {sess.level}L."
        )

    if not student.face_descriptor_json and not student.webauthn_credential_id:
        raise HTTPException(
            status_code=403,
            detail=f"Student {matric} has not enrolled their biometrics with the Level Course Rep yet."
        )

    confidence = 0.98
    if item.verification_method == "FACE_BIOMETRIC_KIOSK" and item.face_descriptor and student.face_descriptor_json:
        stored_vec = json.loads(student.face_descriptor_json)
        if len(item.face_descriptor) == len(stored_vec):
            sim = compute_cosine_similarity(item.face_descriptor, stored_vec)
            confidence = round(max(sim, 0.92), 4)
            if sim < 0.65:
                raise HTTPException(
                    status_code=403,
                    detail="Biometric face signature mismatch! Impersonation blocked."
                )
    elif item.verification_method == "DEVICE_FINGERPRINT_PASSKEY" and item.webauthn_credential_id:
        if student.webauthn_credential_id and item.webauthn_credential_id != student.webauthn_credential_id:
            raise HTTPException(
                status_code=403,
                detail="Device Passkey mismatch! This phone is registered to a different student."
            )

    existing = db.query(AttendanceRecord).filter(
        AttendanceRecord.session_id == sess.id,
        AttendanceRecord.student_id == student.id
    ).first()
    if existing:
        return {
            "status": "already_marked",
            "matric_no": student.matric_no,
            "full_name": student.full_name,
            "confidence_score": existing.confidence_score,
            "lecturer_on_duty": sess.started_by,
            "session_uid": sess.session_uid,
        }

    rec = AttendanceRecord(
        session_id=sess.id,
        course_id=sess.course_id,
        student_id=student.id,
        matric_no=student.matric_no,
        verification_method=item.verification_method,
        confidence_score=confidence,
        captured_offline=item.captured_offline,
        client_timestamp=item.client_timestamp or datetime.now(timezone.utc).isoformat(),
    )
    db.add(rec)
    db.commit()
    return {
        "status": "verified",
        "matric_no": student.matric_no,
        "full_name": student.full_name,
        "verification_method": item.verification_method,
        "confidence_score": confidence,
        "captured_offline": item.captured_offline,
        "lecturer_on_duty": sess.started_by,
        "session_uid": sess.session_uid,
    }


@router.post("/attendance/checkin")
@router.post("/api/attendance/checkin")
def check_in_student(
    payload: BiometricCheckInRequest,
    claims: Dict[str, Any] = Depends(verify_access_token),
    db: Session = Depends(get_db),
):
    if claims.get("role") == "student" and claims.get("matric_no") != payload.matric_no.strip().upper():
        raise HTTPException(
            status_code=403,
            detail="Anti-Impersonation Block: You can only check in with your own authenticated Student Profile!"
        )
    allowed_cid = claims.get("course_id") if claims.get("role") == "lecturer" else None
    result = _process_single_checkin(payload, db, allowed_course_id=allowed_cid)
    return {
        "message": f"Biometric attendance verified for {result['full_name']} (Class taught by {result.get('lecturer_on_duty', 'Lecturer')})",
        "record": result
    }


@router.post("/attendance/sync-offline")
@router.post("/api/attendance/sync-offline")
def sync_offline_attendance(
    payload: OfflineBulkSyncRequest,
    claims: Dict[str, Any] = Depends(verify_access_token),
    db: Session = Depends(get_db),
):
    if claims.get("role") not in ("courserep", "lecturer", "hod"):
        raise HTTPException(status_code=403, detail="Only an authenticated Course Rep, Lecturer, or HOD can sync offline logs.")
    allowed_cid = claims.get("course_id") if claims.get("role") == "lecturer" else None
    synced = []
    errors = []
    for item in payload.records:
        try:
            item.captured_offline = True
            res = _process_single_checkin(item, db, allowed_course_id=allowed_cid)
            synced.append(res)
        except HTTPException as he:
            errors.append({"matric_no": item.matric_no, "error": he.detail})
        except Exception as e:
            errors.append({"matric_no": item.matric_no, "error": str(e)})
    return {
        "message": f"Synced {len(synced)} offline biometric attendance records to HOD database.",
        "synced_count": len(synced),
        "error_count": len(errors),
        "synced": synced,
        "errors": errors,
    }


@router.get("/hod/eligibility")
@router.get("/api/hod/eligibility")
def hod_exam_eligibility_report(
    department_id: int = Query(...),
    level: Optional[int] = Query(None),
    semester: Optional[int] = Query(None),
    course_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    dept = db.query(Department).filter(Department.id == department_id).first()
    if not dept:
        raise HTTPException(status_code=404, detail="Department not found")

    courses_q = db.query(Course).filter(Course.department_id == department_id)
    if level:
        courses_q = courses_q.filter(Course.level == level)
    if semester in (1, 2):
        courses_q = courses_q.filter(Course.semester == semester)
    if course_id:
        courses_q = courses_q.filter(Course.id == course_id)
    courses = courses_q.order_by(Course.level, Course.semester, Course.course_code).all()

    course_reports = []
    total_eligible_instances = 0
    total_barred_instances = 0

    for c in courses:
        course_sessions = db.query(LectureSession).filter(LectureSession.course_id == c.id).order_by(LectureSession.week_number.asc(), LectureSession.id.asc()).all()
        total_sessions = len(course_sessions)
        assigned_list = parse_assigned_lecturers(c.lecturer_name)

        # Build Co-Lecturer Attribution Breakdown (who taught which class and how many sessions)
        lect_stats_map: Dict[str, Dict[str, Any]] = {
            ln: {"lecturer_name": ln, "sessions_taught": 0, "weeks": []} for ln in assigned_list
        }
        sessions_summary = []
        for s in course_sessions:
            teacher = (s.started_by or assigned_list[0]).strip()
            if teacher not in lect_stats_map:
                lect_stats_map[teacher] = {"lecturer_name": teacher, "sessions_taught": 0, "weeks": []}
            lect_stats_map[teacher]["sessions_taught"] += 1
            lect_stats_map[teacher]["weeks"].append(s.week_number)
            present_cnt = db.query(AttendanceRecord).filter(AttendanceRecord.session_id == s.id).count()
            sessions_summary.append({
                "session_uid": s.session_uid,
                "week_number": s.week_number,
                "topic": s.topic,
                "taught_by": teacher,
                "status": s.status,
                "present_count": present_cnt,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            })

        students = db.query(Student).filter(
            Student.department_id == department_id,
            Student.level == c.level
        ).order_by(Student.matric_no).all()

        student_rows = []
        eligible_count = 0
        barred_count = 0

        for st in students:
            attended = db.query(AttendanceRecord).filter(
                AttendanceRecord.course_id == c.id,
                AttendanceRecord.student_id == st.id
            ).count()
            pct = round((attended / total_sessions) * 100.0, 1) if total_sessions > 0 else 100.0
            is_eligible = pct >= dept.min_attendance_pct
            if total_sessions > 0:
                if is_eligible:
                    eligible_count += 1
                    total_eligible_instances += 1
                else:
                    barred_count += 1
                    total_barred_instances += 1

            classes_needed = 0
            if not is_eligible and total_sessions > 0:
                target = math.ceil((dept.min_attendance_pct / 100.0) * total_sessions)
                classes_needed = max(0, target - attended)

            student_rows.append({
                "student_id": st.id,
                "matric_no": st.matric_no,
                "full_name": st.full_name,
                "email": st.email,
                "biometric_enrolled": bool(st.face_descriptor_json or st.webauthn_credential_id),
                "attended_classes": attended,
                "total_classes": total_sessions,
                "attendance_pct": pct,
                "exam_eligible": is_eligible,
                "status_badge": "ELIGIBLE (≥70%)" if is_eligible else "BARRED (<70%)",
                "shortfall_classes": classes_needed,
            })

        course_reports.append({
            "course_id": c.id,
            "course_code": c.course_code,
            "course_title": c.course_title,
            "level": c.level,
            "semester": c.semester or 1,
            "credit_units": c.credit_units,
            "lecturer_name": c.lecturer_name,
            "assigned_lecturers": assigned_list,
            "lecturer_breakdown": list(lect_stats_map.values()),
            "sessions_log": sessions_summary,
            "total_sessions_held": total_sessions,
            "total_students": len(students),
            "eligible_count": eligible_count,
            "barred_count": barred_count,
            "students": student_rows,
        })

    return {
        "department": {
            "id": dept.id,
            "code": dept.code,
            "name": dept.name,
            "hod_name": dept.hod_name,
            "hod_email": dept.hod_email,
            "min_attendance_pct": dept.min_attendance_pct,
        },
        "summary": {
            "courses_analyzed": len(course_reports),
            "total_eligible_entries": total_eligible_instances,
            "total_barred_entries": total_barred_instances,
        },
        "courses": course_reports,
    }


@router.get("/student/lookup")
@router.get("/api/student/lookup")
def student_personal_status(
    matric_no: str = Query(...),
    semester: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    matric = matric_no.strip().upper()
    st = db.query(Student).filter(Student.matric_no == matric).first()
    if not st:
        raise HTTPException(status_code=404, detail=f"Matric number {matric} not found.")

    dept = db.query(Department).filter(Department.id == st.department_id).first()
    courses_q = db.query(Course).filter(
        Course.department_id == st.department_id,
        Course.level == st.level
    )
    if semester in (1, 2):
        courses_q = courses_q.filter(Course.semester == semester)
    courses = courses_q.order_by(Course.semester, Course.course_code).all()

    course_breakdown = []
    for c in courses:
        total_sessions = db.query(LectureSession).filter(LectureSession.course_id == c.id).count()
        attended = db.query(AttendanceRecord).filter(
            AttendanceRecord.course_id == c.id,
            AttendanceRecord.student_id == st.id
        ).count()
        pct = round((attended / total_sessions) * 100.0, 1) if total_sessions > 0 else 100.0
        eligible = pct >= (dept.min_attendance_pct if dept else 70.0)
        course_breakdown.append({
            "course_code": c.course_code,
            "course_title": c.course_title,
            "semester": c.semester or 1,
            "lecturer_name": c.lecturer_name,
            "attended": attended,
            "total_sessions": total_sessions,
            "percentage": pct,
            "exam_eligible": eligible,
        })

    return {
        "student": {
            "id": st.id,
            "matric_no": st.matric_no,
            "full_name": st.full_name,
            "email": st.email,
            "level": st.level,
            "department_name": dept.name if dept else "Engineering",
            "department_code": dept.code if dept else "ENG",
            "has_face_biometric": bool(st.face_descriptor_json),
            "has_passkey": bool(st.webauthn_credential_id),
        },
        "courses": course_breakdown,
    }


app.include_router(router)

PUBLIC_DIR = Path(__file__).resolve().parent.parent / "public"


@app.get("/", response_class=HTMLResponse)
def serve_spa_root():
    index_file = PUBLIC_DIR / "index.html"
    if index_file.exists():
        return index_file.read_text(encoding="utf-8")
    return "<h1>EngAttend API Active</h1>"


@app.get("/manifest.json")
def serve_manifest():
    return FileResponse(PUBLIC_DIR / "manifest.json", media_type="application/json")


@app.get("/sw.js")
def serve_sw():
    return FileResponse(PUBLIC_DIR / "sw.js", media_type="application/javascript")
