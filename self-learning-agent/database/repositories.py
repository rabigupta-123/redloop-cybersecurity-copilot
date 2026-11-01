from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Generator, List, Optional
from sqlalchemy.orm import Session

from database.connection import SessionLocal
from database.models import (
    AgentStats,
    ErrorExample,
    Experience,
    FineTuneJob,
    TrainingExample,
    utc_now,
)


@contextmanager
def get_repo_session(session: Optional[Session] = None) -> Generator[Session, None, None]:
    """Yield given session or create a new one, committing on exit."""
    if session is not None:
        yield session
    else:
        db = SessionLocal()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()


class ExperienceRepo:
    def create(self, db: Optional[Session] = None, **kwargs) -> Experience:
        with get_repo_session(db) as s:
            exp = Experience(**kwargs)
            s.add(exp)
            s.flush()
            s.refresh(exp)
            return exp

    def get_by_type(self, problem_type: str, limit: int = 10, db: Optional[Session] = None) -> List[Experience]:
        with get_repo_session(db) as s:
            return (
                s.query(Experience)
                .filter(Experience.problem_type == problem_type)
                .order_by(Experience.confidence.desc())
                .limit(limit)
                .all()
            )

    def get_all(self, db: Optional[Session] = None) -> List[Experience]:
        with get_repo_session(db) as s:
            return s.query(Experience).all()

    def get_by_id(self, exp_id: int, db: Optional[Session] = None) -> Optional[Experience]:
        with get_repo_session(db) as s:
            return s.query(Experience).filter(Experience.id == exp_id).first()

    def increment_success(self, exp_id: int, db: Optional[Session] = None) -> None:
        with get_repo_session(db) as s:
            exp = s.query(Experience).filter(Experience.id == exp_id).first()
            if exp:
                exp.success_count += 1
                exp.last_used = utc_now()
                s.flush()

    def update_confidence(self, exp_id: int, new_confidence: float, db: Optional[Session] = None) -> None:
        with get_repo_session(db) as s:
            exp = s.query(Experience).filter(Experience.id == exp_id).first()
            if exp:
                exp.confidence = new_confidence
                s.flush()


class ErrorRepo:
    def create(self, db: Optional[Session] = None, **kwargs) -> ErrorExample:
        with get_repo_session(db) as s:
            err = ErrorExample(**kwargs)
            s.add(err)
            s.flush()
            s.refresh(err)
            return err

    def get_by_category(self, category: str, db: Optional[Session] = None) -> List[ErrorExample]:
        with get_repo_session(db) as s:
            return s.query(ErrorExample).filter(ErrorExample.error_category == category).all()

    def get_unfixed_after(self, cutoff: datetime, db: Optional[Session] = None) -> List[ErrorExample]:
        with get_repo_session(db) as s:
            return (
                s.query(ErrorExample)
                .filter(ErrorExample.is_fixed == False, ErrorExample.last_seen >= cutoff)
                .all()
            )

    def get_by_id(self, err_id: int, db: Optional[Session] = None) -> Optional[ErrorExample]:
        with get_repo_session(db) as s:
            return s.query(ErrorExample).filter(ErrorExample.id == err_id).first()

    def get_all(self, db: Optional[Session] = None) -> List[ErrorExample]:
        with get_repo_session(db) as s:
            return s.query(ErrorExample).all()

    def increment_occurrence(self, err_id: int, db: Optional[Session] = None) -> None:
        with get_repo_session(db) as s:
            err = s.query(ErrorExample).filter(ErrorExample.id == err_id).first()
            if err:
                err.occurrence_count += 1
                err.last_seen = utc_now()
                s.flush()

    def mark_fixed(self, err_id: int, db: Optional[Session] = None) -> None:
        with get_repo_session(db) as s:
            err = s.query(ErrorExample).filter(ErrorExample.id == err_id).first()
            if err:
                err.is_fixed = True
                s.flush()


class TrainingRepo:
    def create(self, db: Optional[Session] = None, **kwargs) -> TrainingExample:
        with get_repo_session(db) as s:
            te = TrainingExample(**kwargs)
            s.add(te)
            s.flush()
            s.refresh(te)
            return te

    def get_high_quality(self, min_score: float = 0.8, db: Optional[Session] = None) -> List[TrainingExample]:
        with get_repo_session(db) as s:
            return s.query(TrainingExample).filter(TrainingExample.quality_score >= min_score).all()

    def get_all(self, db: Optional[Session] = None) -> List[TrainingExample]:
        with get_repo_session(db) as s:
            return s.query(TrainingExample).all()


class StatsRepo:
    def record_interaction(
        self,
        correct: bool,
        confidence: float,
        tokens: int,
        response_time: float,
        db: Optional[Session] = None,
    ) -> AgentStats:
        with get_repo_session(db) as s:
            stat = AgentStats(
                total_interactions=1,
                correct_interactions=1 if correct else 0,
                avg_confidence=confidence,
                avg_response_time_ms=response_time,
                tokens_used=tokens,
            )
            s.add(stat)
            s.flush()
            s.refresh(stat)
            return stat

    def get_recent(self, limit: int = 7, db: Optional[Session] = None) -> List[AgentStats]:
        with get_repo_session(db) as s:
            return s.query(AgentStats).order_by(AgentStats.date.desc()).limit(limit).all()


class FineTuneJobRepo:
    def create(self, db: Optional[Session] = None, **kwargs) -> FineTuneJob:
        with get_repo_session(db) as s:
            job = FineTuneJob(**kwargs)
            s.add(job)
            s.flush()
            s.refresh(job)
            return job

    def get(self, job_id: int, db: Optional[Session] = None) -> Optional[FineTuneJob]:
        with get_repo_session(db) as s:
            return s.query(FineTuneJob).filter(FineTuneJob.id == job_id).first()

    def update(self, job: FineTuneJob, db: Optional[Session] = None) -> None:
        with get_repo_session(db) as s:
            s.merge(job)
            s.flush()


# Global singleton instances
experience_repo = ExperienceRepo()
error_repo = ErrorRepo()
training_example_repo = TrainingRepo()
agent_stats_repo = StatsRepo()
finetune_job_repo = FineTuneJobRepo()
