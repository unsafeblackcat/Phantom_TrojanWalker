import asyncio
import logging
import traceback
from datetime import datetime
from sqlalchemy.orm import Session

from backend.database import SessionLocal
from backend.models.task import AnalysisTask
from backend.core.factory import create_coordinator

logger = logging.getLogger(__name__)


class AnalysisWorker:
    def __init__(self):
        self.queue = asyncio.Queue()
        self.coordinator = None
        self._running = False
        self._analysis_lock = asyncio.Lock()  # Explicit lock to ensure only one analysis runs at a time

    def _requeue_unfinished_tasks(self):
        db: Session = SessionLocal()
        try:
            tasks = (
                db.query(AnalysisTask)
                .filter(AnalysisTask.status.in_(["pending", "processing"]))
                .order_by(AnalysisTask.created_at.asc())
                .all()
            )
            if not tasks:
                return

            # Any "processing" tasks were interrupted; mark them pending and requeue.
            for t in tasks:
                if t.status == "processing":
                    t.status = "pending"
            db.commit()

            for t in tasks:
                self.queue.put_nowait(t.id)
            logger.info("Re-queued %d unfinished task(s) on startup.", len(tasks))
        except Exception:
            logger.error("Failed to re-queue unfinished tasks on startup", exc_info=True)
        finally:
            db.close()

    async def start(self):
        self.coordinator = create_coordinator()
        self._running = True
        logger.info("AnalysisWorker started.")
        self._requeue_unfinished_tasks()
        asyncio.create_task(self.process_queue())

    async def process_queue(self):
        while self._running:
            task_id = await self.queue.get()
            try:
                # Use lock to strictly enforce single analysis.
                async with self._analysis_lock:
                    await self.run_analysis(task_id)
            except Exception as e:
                logger.error(f"Error processing task {task_id}: {e}")
            finally:
                self.queue.task_done()

    async def run_analysis(self, task_id: int):
        db: Session = SessionLocal()
        try:
            task = self._fetch_task(db, task_id)
            if not task:
                return

            self._mark_processing(task, db)

            content = self._read_file_content(task, db)
            if content is None:
                return

            await self._run_analysis_pipeline(task, content, db)
        except Exception as e:
            logger.error(f"Worker DB Error: {e}")
        finally:
            db.close()

    def _fetch_task(self, db: Session, task_id: int) -> AnalysisTask | None:
        """Fetch task row and handle missing record.

        Refactor note: keep DB lookup logic in one place.
        """
        task = db.query(AnalysisTask).filter(AnalysisTask.id == task_id).first()
        if not task:
            logger.error(f"Task {task_id} not found in DB.")
            return None
        return task

    def _mark_processing(self, task: AnalysisTask, db: Session) -> None:
        """Mark task as processing and persist immediately."""
        logger.info(f"Processing task {task.task_id} ({task.filename})")
        task.status = "processing"
        db.commit()

    def _read_file_content(self, task: AnalysisTask, db: Session) -> bytes | None:
        """Read binary content from disk and persist error on failure."""
        try:
            with open(task.file_path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            # Guard clause keeps error handling close to the failure.
            task.status = "failed"
            task.error_message = "File not found on disk."
            db.commit()
            return None

    async def _run_analysis_pipeline(self, task: AnalysisTask, content: bytes, db: Session) -> None:
        """Run analysis pipeline and update task fields.

        Refactor note: isolate the analysis path from DB orchestration.
        """
        try:
            # Use sha256 as a safe, stable filename when talking to downstream analyzers.
            # Keep original task.filename only for display/logging.
            result = await self.coordinator.analyze_content(task.sha256, content)
            task.status = "completed"

            # Unpack result into columns
            task.metadata_info = result.get("metadata")
            task.functions = result.get("functions")
            task.strings = result.get("strings")
            task.decompiled_code = result.get("decompiled_code")
            task.function_analyses = result.get("function_analyses")
            task.malware_report = result.get("malware_report")

            task.finished_at = datetime.now()
        except Exception as e:
            logger.error(f"Analysis failed: {traceback.format_exc()}")
            task.status = "failed"
            task.error_message = str(e)
        finally:
            db.commit()

    def add_task(self, task_id: int):
        self.queue.put_nowait(task_id)


worker = AnalysisWorker()
