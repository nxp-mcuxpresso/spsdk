#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK EL2GO bulk operations for job-based secure objects download.

This module provides functionality for managing bulk download operations
of secure objects from EL2GO service using job-based processing approach.
"""

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
    """EL2GO job information container.

    This class represents a bulk provisioning job with tracking capabilities
    for device processing status, timing, and completion metrics.
    """

    job_id: str
    device_count: int
    created_at: datetime = datetime.now(timezone.utc)
    updated_at: Optional[datetime] = None
    status: Optional[str] = None
    percentage: int = 0
    downloaded: int = 0

    def __str__(self) -> str:
        """Return string representation of the bulk provisioning job.

        :return: Formatted string containing job ID and device count.
        """
        return f"Job {self.job_id} with {self.device_count} devices"

    @classmethod
    def from_tuple(cls, info: tuple) -> Self:
        """Create JobInfo instance from database record.

        :param info: Tuple containing job information from database in order: job_id, device_count,
            created_at, updated_at, status, percentage, downloaded.
        :raises IndexError: Invalid tuple structure or missing required fields.
        :raises ValueError: Invalid data format in tuple fields.
        :return: New JobInfo instance populated with data from the tuple.
        """
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
        """Calculate remaining time for the job to finish.

        The method estimates completion time based on current progress percentage and elapsed time.
        For completed jobs (100% progress), returns None. For jobs at 0% progress, uses the
        provided time_per_device estimate. For jobs in progress, calculates speed based on
        current progress and estimates remaining time.

        :param time_per_device: Estimated processing time per device in seconds.
        :return: Estimated remaining time in seconds, or None if job is completed.
        """
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
        """Check if the job is completed.

        :return: True if the job completion percentage is 100, False otherwise.
        """
        return self.percentage == 100

    def should_update(self) -> bool:
        """Check if the job should be updated.

        Determines whether a job requires updating based on completion status and elapsed time
        since last update. A job should be updated if it's not completed and the elapsed time
        exceeds the calculated wait time.

        :return: True if job should be updated, False otherwise.
        """
        if self.is_completed():
            return False
        elapsed_time = datetime.now(timezone.utc) - (self.updated_at or self.created_at)
        logger.debug(f"Elapsed time: {elapsed_time.total_seconds()}")
        return elapsed_time.total_seconds() > (self.calc_wait_time() or 0)


class ServiceDB(LocalSecureObjectsDB):
    """SPSDK Service Database for EL2GO bulk operations.

    This class extends LocalSecureObjectsDB to manage job information for EL2GO
    bulk provisioning operations. It provides persistent storage and retrieval
    of job status, progress tracking, and device count management through a
    SQLite database with a dedicated jobs table.
    """

    def _setup_db(self) -> None:
        """Set up the database schema for bulk provisioning operations.

        Creates the jobs table if it doesn't exist, which stores information about
        bulk provisioning jobs including their status, progress, and metadata.

        :raises SPSDKError: If database setup or table creation fails.
        """
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
        """Insert new job into the database.

        The method creates a new job record with the provided job ID, current timestamp,
        and device count in the jobs table.

        :param job_id: Unique identifier for the job to be inserted.
        :param device_count: Number of devices associated with this job.
        """
        logger.info(f"Inserting job {job_id}")
        cursor = self._sanitize_cursor()
        cursor.execute(
            "INSERT INTO jobs (job_id, created_at, device_count) VALUES (?, ?, ?)",
            (job_id, datetime.now(timezone.utc), device_count),
        )
        cursor.connection.commit()

    def update_job(self, job_id: str, status: str, percentage: int = 0) -> None:
        """Update job status in the database.

        Updates the job record with new status, percentage completion, and timestamp.
        The method automatically commits the changes to the database.

        :param job_id: Unique identifier of the job to update.
        :param status: New status value for the job.
        :param percentage: Completion percentage of the job (default is 0).
        """
        logger.info(f"Updating job {job_id} with status {status}")
        cursor = self._sanitize_cursor()
        cursor.execute(
            "UPDATE jobs SET status = ?, updated_at = ?, percentage = ? WHERE job_id = ?",
            (status, datetime.now(timezone.utc), percentage, job_id),
        )
        cursor.connection.commit()

    def get_incomplete_jobs(self) -> list[JobInfo]:
        """Get list of incomplete jobs.

        Retrieves all jobs from the database that have a completion percentage less than 100%.
        The method queries the jobs table and returns JobInfo objects for all incomplete jobs.

        :return: List of JobInfo objects representing incomplete jobs.
        """
        logger.debug("Getting incomplete jobs")
        cursor = self._sanitize_cursor()
        cursor.execute("SELECT * FROM jobs WHERE percentage < 100")
        jobs: list[JobInfo] = []
        for info in cursor.fetchall():
            job = JobInfo.from_tuple(info)
            jobs.append(job)
        return jobs

    def get_successful_jobs(self) -> list[JobInfo]:
        """Get list of successful jobs.

        Retrieves all jobs that have completed successfully from the bulk operation.

        :return: List of JobInfo objects representing successful jobs.
        """
        logger.debug("Getting successful jobs")
        return self._get_jobs_by_status(failed=False)

    def get_failed_jobs(self) -> list[JobInfo]:
        """Get list of failed jobs.

        Retrieves all jobs that have failed status from the bulk operation.

        :return: List of JobInfo objects representing failed jobs.
        """
        logger.debug("Getting failed jobs")
        return self._get_jobs_by_status(failed=True)

    def _get_jobs_by_status(self, failed: bool) -> list[JobInfo]:
        """Get list of jobs by status.

        Retrieves jobs from the database filtered by their completion status.
        Uses SQL query to fetch job records and converts them to JobInfo objects.

        :param failed: If True, returns failed jobs; if False, returns successfully completed jobs.
        :return: List of JobInfo objects matching the specified status criteria.
        """
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
        """Get list of jobs with Secure Objects to download.

        Retrieves all completed jobs (100% progress) that have not been downloaded yet from the database.

        :return: List of job information objects for jobs ready to download.
        """
        logger.debug("Getting jobs to download")
        cursor = self._sanitize_cursor()
        cursor.execute("SELECT * FROM jobs WHERE percentage == 100 AND downloaded = 0")
        jobs: list[JobInfo] = []
        for info in cursor.fetchall():
            job = JobInfo.from_tuple(info)
            jobs.append(job)
        return jobs

    def set_downloaded(self, job_id: str) -> None:
        """Mark job as downloaded.

        Updates the database to set the downloaded flag to 1 for the specified job.

        :param job_id: Unique identifier of the job to mark as downloaded.
        """
        logger.info(f"Setting job {job_id} as downloaded")
        cursor = self._sanitize_cursor()
        cursor.execute("UPDATE jobs SET downloaded = 1 WHERE job_id = ?", (job_id,))
        cursor.connection.commit()
