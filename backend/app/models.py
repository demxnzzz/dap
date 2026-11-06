from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Repository(Base):
    __tablename__ = "repositories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    url: Mapped[str] = mapped_column(String(400), nullable=False)
    platform: Mapped[str] = mapped_column(String(40), default="github")
    source_type: Mapped[str] = mapped_column(String(20), default="github")
    default_branch: Mapped[str] = mapped_column(String(120), default="main")
    owner: Mapped[str | None] = mapped_column(String(160))
    repo_slug: Mapped[str | None] = mapped_column(String(160))
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    commits: Mapped[list["CommitRecord"]] = relationship(
        back_populates="repository", cascade="all, delete-orphan"
    )
    assets: Mapped[list["Asset"]] = relationship(
        back_populates="repository", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="repository", cascade="all, delete-orphan"
    )
    reports: Mapped[list["Report"]] = relationship(
        back_populates="repository", cascade="all, delete-orphan"
    )


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint(
            "repository_id", "method", "path", "file_path", name="uq_asset_identity"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repository_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"), index=True
    )
    method: Mapped[str] = mapped_column(String(12), default="GET")
    path: Mapped[str] = mapped_column(String(400), nullable=False)
    file_path: Mapped[str] = mapped_column(String(400), default="")
    framework: Mapped[str] = mapped_column(String(40), default="unknown")
    params: Mapped[list] = mapped_column(JSON, default=list)
    notes: Mapped[str] = mapped_column(Text, default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    repository: Mapped[Repository] = relationship(back_populates="assets")


class CommitRecord(Base):
    __tablename__ = "commits"
    __table_args__ = (
        UniqueConstraint("repository_id", "sha", name="uq_commit_sha_per_repo"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repository_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"), index=True
    )
    sha: Mapped[str] = mapped_column(String(80), nullable=False)
    message: Mapped[str] = mapped_column(Text, default="")
    author: Mapped[str] = mapped_column(String(160), default="unknown")
    committed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    files_changed: Mapped[int] = mapped_column(Integer, default=0)
    additions: Mapped[int] = mapped_column(Integer, default=0)
    deletions: Mapped[int] = mapped_column(Integer, default=0)
    risk_level: Mapped[str] = mapped_column(String(12), default="low")
    risk_reasons: Mapped[list] = mapped_column(JSON, default=list)
    reviewed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    repository: Mapped[Repository] = relationship(back_populates="commits")
    files: Mapped[list["DiffFile"]] = relationship(
        back_populates="commit", cascade="all, delete-orphan"
    )


class DiffFile(Base):
    __tablename__ = "diff_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    commit_id: Mapped[int] = mapped_column(
        ForeignKey("commits.id", ondelete="CASCADE"), index=True
    )
    filename: Mapped[str] = mapped_column(String(400), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="modified")
    additions: Mapped[int] = mapped_column(Integer, default=0)
    deletions: Mapped[int] = mapped_column(Integer, default=0)
    patch: Mapped[str] = mapped_column(Text, default="")
    is_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    sensitive_reasons: Mapped[list] = mapped_column(JSON, default=list)

    commit: Mapped[CommitRecord] = relationship(back_populates="files")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repository_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"), index=True
    )
    asset_id: Mapped[int | None] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(400), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(20), default="manual")
    rule_id: Mapped[str] = mapped_column(String(300), default="")
    severity: Mapped[str] = mapped_column(String(12), default="medium")
    status: Mapped[str] = mapped_column(String(20), default="new")
    file_path: Mapped[str] = mapped_column(String(400), default="")
    line: Mapped[int | None] = mapped_column(Integer)
    cvss_vector: Mapped[str] = mapped_column(String(200), default="")
    cvss_score: Mapped[float | None] = mapped_column(Float)
    dedupe_key: Mapped[str | None] = mapped_column(
        String(80), unique=True, index=True
    )
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    repository: Mapped[Repository] = relationship(back_populates="findings")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repository_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"), index=True
    )
    finding_id: Mapped[int | None] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(400), nullable=False)
    target: Mapped[str] = mapped_column(String(300), default="")
    researcher: Mapped[str] = mapped_column(String(160), default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    steps: Mapped[str] = mapped_column(Text, default="")
    root_cause: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[str] = mapped_column(Text, default="")
    cvss_vector: Mapped[str] = mapped_column(String(200), default="")
    cvss_score: Mapped[float | None] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(12), default="medium")
    platform: Mapped[str] = mapped_column(String(60), default="HackerOne")
    status: Mapped[str] = mapped_column(String(20), default="draft")
    markdown: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    repository: Mapped[Repository] = relationship(back_populates="reports")


class ModelState(Base):
    """A declared state in the analyst's state machine."""

    __tablename__ = "model_states"
    __table_args__ = (
        UniqueConstraint("repository_id", "name", name="uq_state_name_per_repo"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repository_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), default="normal")
    trust: Mapped[str] = mapped_column(String(16), default="unknown")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ModelTransition(Base):
    """A declared (or merely permitted) move between two states."""

    __tablename__ = "model_transitions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repository_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"), index=True
    )
    event: Mapped[str] = mapped_column(String(120), nullable=False)
    from_state: Mapped[str] = mapped_column(String(120), nullable=False)
    to_state: Mapped[str] = mapped_column(String(120), nullable=False)
    cross_boundary: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Invariant(Base):
    __tablename__ = "invariants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repository_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    statement: Mapped[str] = mapped_column(Text, default="")
    rule_type: Mapped[str] = mapped_column(String(40), default="")
    event: Mapped[str] = mapped_column(String(120), default="")
    from_state: Mapped[str] = mapped_column(String(120), default="")
    to_state: Mapped[str] = mapped_column(String(120), default="")
    requires_event: Mapped[str] = mapped_column(String(120), default="")
    severity: Mapped[str] = mapped_column(String(12), default="medium")
    status: Mapped[str] = mapped_column(String(20), default="draft")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repository_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"), index=True
    )
    invariant_id: Mapped[int | None] = mapped_column(
        ForeignKey("invariants.id", ondelete="CASCADE"), index=True
    )
    depth: Mapped[int] = mapped_column(Integer, default=8)
    outcome: Mapped[str] = mapped_column(String(20), default="inconclusive")
    reason: Mapped[str] = mapped_column(Text, default="")
    trace: Mapped[list] = mapped_column(JSON, default=list)
    traces_explored: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
