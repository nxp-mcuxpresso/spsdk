#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module to support bulk (job-based) EL2GO Secure Objects download."""

import logging
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from typing_extensions import Self

from spsdk.el2go.database import LocalSecureObjectsDB

logger = logging.getLogger(__name__)


@dataclass
class JobInfo:
    """Dataclass for storing information about a job."""

    job_id: str
    device_count: int
    created_at: datetime = datetime.now(timezone.utc)
    updated_at: Optional[datetime] = None
    status: Optional[str] = None
    percentage: int = 0
    downloaded: int = 0

    def __str__(self) -> str:
        return f"Job {self.job_id} with {self.device_count} devices"

    @classmethod
    def from_tuple(cls, info: tuple) -> Self:
        """Create JobInfo instance from database record."""
        return cls(
            job_id=info[0],
            device_count=int(info[1]),
            created_at=datetime.fromisoformat(info[2]),
            updated_at=datetime.fromisoformat(info[3]) if info[3] else None,
            status=info[4],
            percentage=int(info[5]),
            downloaded=int(info[6]),
        )

    def calc_wait_time(self, time_per_device: float = 5.0) -> Optional[float]:
        """Calculate remaining time for the job to finish."""
        if self.percentage == 100:
            return None

        elapsed_time = datetime.now(timezone.utc) - (self.updated_at or self.created_at)

        if self.percentage == 0:
            return max(0.0, self.device_count * time_per_device - elapsed_time.total_seconds())

        already_done = math.ceil(self.device_count * self.percentage / 100)
        speed = already_done / elapsed_time.total_seconds()
        remaining = self.device_count - already_done
        remaining_time = remaining / speed
        return remaining_time

    def is_completed(self) -> bool:
        """Check if the job is completed."""
        return self.percentage == 100

    def should_update(self) -> bool:
        """Check if the job should be updated."""
        if self.is_completed():
            return False
        elapsed_time = datetime.now(timezone.utc) - (self.updated_at or self.created_at)
        logger.debug(f"Elapsed time: {elapsed_time.total_seconds()}")
        return elapsed_time.total_seconds() > (self.calc_wait_time() or 0)


class ServiceDB(LocalSecureObjectsDB):
    """Database for storing information about jobs."""

    def _setup_db(self) -> None:
        super()._setup_db()
        with self:
            cursor = self._sanitize_cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    device_count INTEGER NOT NULL,
                    created_at datetime NOT NULL,
                    updated_at datetime NULL,
                    status TEXT default TRIGGERED,
                    percentage INTEGER NULL DEFAULT 0,
                    downloaded INTEGER NULL DEFAULT 0
                );
                """
            )
            cursor.connection.commit()

    def insert_job(self, job_id: str, device_count: int) -> None:
        """Insert new job into the database."""
        logger.info(f"Inserting job {job_id}")
        cursor = self._sanitize_cursor()
        cursor.execute(
            "INSERT INTO jobs (job_id, created_at, device_count) VALUES (?, ?, ?)",
            (job_id, datetime.now(timezone.utc), device_count),
        )
        cursor.connection.commit()

    def update_job(self, job_id: str, status: str, percentage: int = 0) -> None:
        """Update job status in the database."""
        logger.info(f"Updating job {job_id} with status {status}")
        cursor = self._sanitize_cursor()
        cursor.execute(
            "UPDATE jobs SET status = ?, updated_at = ?, percentage = ? WHERE job_id = ?",
            (status, datetime.now(timezone.utc), percentage, job_id),
        )
        cursor.connection.commit()

    def get_incomplete_jobs(self) -> list[JobInfo]:
        """Get list of incomplete jobs."""
        logger.debug("Getting incomplete jobs")
        cursor = self._sanitize_cursor()
        cursor.execute("SELECT * FROM jobs WHERE percentage < 100")
        jobs: list[JobInfo] = []
        for info in cursor.fetchall():
            job = JobInfo.from_tuple(info)
            jobs.append(job)
        return jobs

    def get_successful_jobs(self) -> list[JobInfo]:
        """Get list of successful jobs."""
        logger.debug("Getting successful jobs")
        return self._get_jobs_by_status(failed=False)

    def get_failed_jobs(self) -> list[JobInfo]:
        """Get list of failed jobs."""
        logger.debug("Getting failed jobs")
        return self._get_jobs_by_status(failed=True)

    def _get_jobs_by_status(self, failed: bool) -> list[JobInfo]:
        """Get list of jobs by status."""
        cursor = self._sanitize_cursor()
        condition = "!=" if failed else "="
        # SQL injection is not possible here, as the condition is hardcoded
        cmd = f"SELECT * FROM jobs WHERE status {condition} 'COMPLETED_SUCCESSFULLY'"  # nosec
        cursor.execute(cmd)
        jobs: list[JobInfo] = []
        for info in cursor.fetchall():
            job = JobInfo.from_tuple(info)
            jobs.append(job)
        return jobs

    def get_jobs_to_download(self) -> list[JobInfo]:
        """Get list of jobs with Secure Objects to download."""
        logger.debug("Getting jobs to download")
        cursor = self._sanitize_cursor()
        cursor.execute("SELECT * FROM jobs WHERE percentage == 100 AND downloaded = 0")
        jobs: list[JobInfo] = []
        for info in cursor.fetchall():
            job = JobInfo.from_tuple(info)
            jobs.append(job)
        return jobs

    def set_downloaded(self, job_id: str) -> None:
        """Mark job as downloaded."""
        logger.info(f"Setting job {job_id} as downloaded")
        cursor = self._sanitize_cursor()
        cursor.execute("UPDATE jobs SET downloaded = 1 WHERE job_id = ?", (job_id,))
        cursor.connection.commit()
