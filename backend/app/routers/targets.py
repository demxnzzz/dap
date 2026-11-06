from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_db
from ..github_sync import GitHubError, github_token, parse_repo_url, sync_repository
from ..models import Repository
from ..queries import repository_counts
from ..serializers import repo_out

router = APIRouter(prefix="/api", tags=["targets"])


class RepositoryIn(BaseModel):
    name: str | None = None
    url: str


@router.get("/repositories")
def list_repositories(db: Session = Depends(get_db)):
    repositories = db.query(Repository).order_by(Repository.created_at.desc()).all()
    return [
        repo_out(repo, repository_counts(db, repo.id)) for repo in repositories
    ]


@router.post("/repositories", status_code=201)
def create_repository(payload: RepositoryIn, db: Session = Depends(get_db)):
    url = (payload.url or "").strip()
    if not url:
        raise HTTPException(422, "A repository URL is required")

    platform = "github" if "github.com" in url.lower() else "git"
    owner = slug = None
    if platform == "github":
        try:
            owner, slug = parse_repo_url(url)
        except GitHubError as exc:
            raise HTTPException(exc.status_code, exc.message)

    name = (payload.name or "").strip() or slug or url.rstrip("/").split("/")[-1]
    repository = Repository(
        name=name,
        url=url,
        platform=platform,
        source_type="github" if platform == "github" else "manual",
        owner=owner,
        repo_slug=slug,
    )
    db.add(repository)
    db.commit()
    db.refresh(repository)
    return repo_out(repository, repository_counts(db, repository.id))


@router.delete("/repositories/{repo_id}", status_code=204)
def delete_repository(repo_id: int, db: Session = Depends(get_db)):
    repository = db.get(Repository, repo_id)
    if not repository:
        raise HTTPException(404, "Target not found")
    db.delete(repository)
    db.commit()
    return None


@router.post("/repositories/{repo_id}/sync")
async def sync_target(repo_id: int, db: Session = Depends(get_db)):
    repository = db.get(Repository, repo_id)
    if not repository:
        raise HTTPException(404, "Target not found")
    if repository.source_type == "demo":
        raise HTTPException(
            400,
            "The demo workspace is static. Add a real GitHub repository to sync commits and assets.",
        )
    try:
        summary = await sync_repository(db, repository, github_token())
    except GitHubError as exc:
        db.rollback()
        raise HTTPException(exc.status_code, exc.message)
    return {
        "repository": repo_out(repository, repository_counts(db, repository.id)),
        "summary": summary,
    }
