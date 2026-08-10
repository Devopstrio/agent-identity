import os

import asyncpg


class PostgresAdapter:
    def __init__(self) -> None:
        self.dsn = os.getenv("PG_DSN", "postgresql://postgres:postgres@localhost:5432/agent_identity_db")
        self.pool: asyncpg.Pool | None = None

    async def connect(self) -> None:
        if self.pool is None:
            self.pool = await asyncpg.create_pool(self.dsn)
            await self._init_db()

    async def close(self) -> None:
        if self.pool is not None:
            await self.pool.close()

    async def _init_db(self) -> None:
        if self.pool is None:
            return
        async with self.pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS workloads (
                    agent_id VARCHAR(255) PRIMARY KEY,
                    join_token_hash VARCHAR(255) NOT NULL,
                    status VARCHAR(50) DEFAULT 'ACTIVE'
                );
                CREATE TABLE IF NOT EXISTS certificates (
                    serial_number BIGINT PRIMARY KEY,
                    agent_id VARCHAR(255) REFERENCES workloads(agent_id),
                    revoked BOOLEAN DEFAULT FALSE,
                    expires_at TIMESTAMP
                );
            """)

    async def register_workload(self, agent_id: str, join_token_hash: str) -> None:
        await self.connect()
        if self.pool is None:
            raise RuntimeError("Database connection pool is not initialized.")
        async with self.pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO workloads (agent_id, join_token_hash) VALUES ($1, $2) "
                "ON CONFLICT (agent_id) DO UPDATE SET join_token_hash = EXCLUDED.join_token_hash, status = 'ACTIVE'",
                agent_id, join_token_hash
            )

    async def get_join_token_hash(self, agent_id: str) -> str | None:
        await self.connect()
        if self.pool is None:
            raise RuntimeError("Database connection pool is not initialized.")
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT join_token_hash FROM workloads WHERE agent_id = $1 AND status = 'ACTIVE'", agent_id
            )
            return row["join_token_hash"] if row else None

    async def record_certificate(self, serial_number: int, agent_id: str, expires_at: str) -> None:
        await self.connect()
        if self.pool is None:
            raise RuntimeError("Database connection pool is not initialized.")
        async with self.pool.acquire() as conn:
            # Note: expires_at is passed as string for simplicity in this demo, real world uses datetime
            await conn.execute(
                "INSERT INTO certificates (serial_number, agent_id, expires_at) VALUES ($1, $2, $3::timestamp)",
                serial_number, agent_id, expires_at
            )

    async def revoke_certificate(self, serial_number: int) -> bool:
        await self.connect()
        if self.pool is None:
            raise RuntimeError("Database connection pool is not initialized.")
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE certificates SET revoked = TRUE WHERE serial_number = $1", serial_number
            )
            return bool(result == "UPDATE 1")
