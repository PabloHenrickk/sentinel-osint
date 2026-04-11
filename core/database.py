"""
core/database.py — Índice SQLite do Sentinel OSINT

Responsabilidade única: persistir e consultar análises sem substituir os JSON
em data/. O SQLite é um índice — os arquivos JSON continuam sendo a fonte
de verdade. Isso permite queries rápidas sobre histórico sem reprocessar JSON.

Schema:
  targets   — cada alvo analisado (domínio ou IP)
  analyses  — cada execução do ai_analyst por alvo
  findings  — findings individuais de cada análise

Uso:
  from core.database import Database
  db = Database()
  db.save_analysis(target="scanme.nmap.org", analysis=analysis_dict)
  db.get_history("scanme.nmap.org")
  db.get_findings(severity="CRITICAL")
"""

import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

DB_PATH = Path("data/sentinel.db")


class Database:
    """
    Interface SQLite para o Sentinel OSINT.
    Cada instância abre e fecha a conexão por operação — seguro para uso
    em pipeline linear sem threading.
    """

    def __init__(self, db_path: Path = DB_PATH) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    # ── Conexão ───────────────────────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row           # acesso por nome de coluna
        conn.execute("PRAGMA journal_mode=WAL")  # melhor concorrência
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    # ── Schema ────────────────────────────────────────────────────────────

    def _init_schema(self) -> None:
        """Cria tabelas se não existirem. Idempotente."""
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS targets (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    target      TEXT    NOT NULL,
                    target_type TEXT    NOT NULL DEFAULT 'domain',
                    first_seen  TEXT    NOT NULL,
                    last_seen   TEXT    NOT NULL,
                    total_runs  INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(target)
                );

                CREATE TABLE IF NOT EXISTS analyses (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    target          TEXT    NOT NULL,
                    analyzed_at     TEXT    NOT NULL,
                    provider        TEXT,
                    model           TEXT,
                    priority_level  TEXT,
                    risk_level      TEXT,
                    total_findings  INTEGER NOT NULL DEFAULT 0,
                    critical_count  INTEGER NOT NULL DEFAULT 0,
                    high_count      INTEGER NOT NULL DEFAULT 0,
                    medium_count    INTEGER NOT NULL DEFAULT 0,
                    low_count       INTEGER NOT NULL DEFAULT 0,
                    info_count      INTEGER NOT NULL DEFAULT 0,
                    json_path       TEXT,
                    report_path     TEXT,
                    FOREIGN KEY(target) REFERENCES targets(target)
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id     INTEGER NOT NULL,
                    target          TEXT    NOT NULL,
                    finding_id      TEXT,
                    title           TEXT    NOT NULL,
                    severity        TEXT    NOT NULL,
                    category        TEXT,
                    mitre_id        TEXT,
                    mitre_name      TEXT,
                    description     TEXT,
                    source          TEXT,
                    analyzed_at     TEXT    NOT NULL,
                    FOREIGN KEY(analysis_id) REFERENCES analyses(id)
                );

                CREATE INDEX IF NOT EXISTS idx_analyses_target
                    ON analyses(target);
                CREATE INDEX IF NOT EXISTS idx_findings_severity
                    ON findings(severity);
                CREATE INDEX IF NOT EXISTS idx_findings_mitre
                    ON findings(mitre_id);
                CREATE INDEX IF NOT EXISTS idx_findings_target
                    ON findings(target);
            """)

    # ── Escrita ───────────────────────────────────────────────────────────

    def save_analysis(
        self,
        target      : str,
        analysis    : dict,
        json_path   : Optional[str] = None,
        report_path : Optional[str] = None,
    ) -> int:
        """
        Persiste uma análise completa do ai_analyst.
        Retorna o analysis_id gerado.

        Args:
            target      : domínio ou IP analisado
            analysis    : dict retornado pelo ai_analyst.run()
            json_path   : caminho do arquivo JSON salvo em data/
            report_path : caminho do relatório MD em reports/
        """
        now         = datetime.now().isoformat()
        findings    = analysis.get("findings", [])
        counts      = self._count_by_severity(findings)
        target_type = "ip" if self._is_ip(target) else "domain"

        exec_s     = analysis.get("executive_summary", {})
        risk_level = (
            exec_s.get("risk_level") if isinstance(exec_s, dict) else None
        ) or analysis.get("priority_level")

        analyzed_at = analysis.get("analyzed_at", now)

        with self._connect() as conn:
            # Upsert em targets — primeira vez insere, demais atualiza last_seen
            conn.execute("""
                INSERT INTO targets (target, target_type, first_seen, last_seen, total_runs)
                VALUES (?, ?, ?, ?, 1)
                ON CONFLICT(target) DO UPDATE SET
                    last_seen  = excluded.last_seen,
                    total_runs = total_runs + 1
            """, (target, target_type, analyzed_at, analyzed_at))

            # Cada execução do pipeline = 1 linha em analyses
            cursor = conn.execute("""
                INSERT INTO analyses (
                    target, analyzed_at, provider, model,
                    priority_level, risk_level,
                    total_findings, critical_count, high_count,
                    medium_count, low_count, info_count,
                    json_path, report_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                target,
                analyzed_at,
                analysis.get("provider"),
                analysis.get("model"),
                analysis.get("priority_level"),
                risk_level,
                len(findings),
                counts["CRITICAL"],
                counts["HIGH"],
                counts["MEDIUM"],
                counts["LOW"],
                counts["INFO"],
                json_path or analysis.get("saved_to"),
                report_path,
            ))

            analysis_id = cursor.lastrowid

            # Um finding por linha — permite filtrar por severidade/MITRE direto
            for f in findings:
                mitre      = f.get("mitre_attack") or {}
                mitre_id   = (
                    mitre.get("technique_id") if isinstance(mitre, dict) else None
                ) or f.get("mitre_id")
                mitre_name = (
                    mitre.get("technique") if isinstance(mitre, dict) else None
                ) or f.get("mitre_name")

                conn.execute("""
                    INSERT INTO findings (
                        analysis_id, target, finding_id, title,
                        severity, category, mitre_id, mitre_name,
                        description, source, analyzed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    analysis_id,
                    target,
                    f.get("id"),
                    f.get("title", "—"),
                    f.get("severity", "INFO").upper(),
                    f.get("category"),
                    mitre_id,
                    mitre_name,
                    (f.get("description") or "")[:500],
                    f.get("_source"),
                    analyzed_at,
                ))

        return analysis_id

    # ── Leitura ───────────────────────────────────────────────────────────

    def get_history(self, target: str) -> list[dict]:
        """Retorna todas as análises de um alvo, mais recente primeiro."""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT * FROM analyses
                WHERE target = ?
                ORDER BY analyzed_at DESC
            """, (target,)).fetchall()
        return [dict(r) for r in rows]

    def get_findings(
        self,
        severity : Optional[str] = None,
        target   : Optional[str] = None,
        mitre_id : Optional[str] = None,
        limit    : int = 100,
    ) -> list[dict]:
        """
        Consulta findings com filtros opcionais.

        Exemplos:
          db.get_findings(severity="CRITICAL")
          db.get_findings(target="scanme.nmap.org", severity="HIGH")
          db.get_findings(mitre_id="T1557")
        """
        conditions: list[str] = []
        params    : list      = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())
        if target:
            conditions.append("target = ?")
            params.append(target)
        if mitre_id:
            conditions.append("mitre_id = ?")
            params.append(mitre_id)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        with self._connect() as conn:
            rows = conn.execute(f"""
                SELECT * FROM findings
                {where}
                ORDER BY analyzed_at DESC
                LIMIT ?
            """, (*params, limit)).fetchall()
        return [dict(r) for r in rows]

    def get_targets(self) -> list[dict]:
        """Lista todos os alvos já analisados com contagem de runs."""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT t.*,
                       a.risk_level     as last_risk,
                       a.total_findings as last_findings
                FROM targets t
                LEFT JOIN analyses a ON a.target = t.target
                    AND a.analyzed_at = (
                        SELECT MAX(analyzed_at) FROM analyses WHERE target = t.target
                    )
                ORDER BY t.last_seen DESC
            """).fetchall()
        return [dict(r) for r in rows]

    def get_summary(self) -> dict:
        """Resumo geral do banco — útil para CLI e dashboard futuro."""
        with self._connect() as conn:
            total_targets  = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
            total_analyses = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
            total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            critical_total = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE severity='CRITICAL'"
            ).fetchone()[0]
            high_total = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE severity='HIGH'"
            ).fetchone()[0]

        return {
            "total_targets"  : total_targets,
            "total_analyses" : total_analyses,
            "total_findings" : total_findings,
            "critical_total" : critical_total,
            "high_total"     : high_total,
        }

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _count_by_severity(findings: list[dict]) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "INFO").upper()
            if sev in counts:
                counts[sev] += 1
        return counts

    @staticmethod
    def _is_ip(target: str) -> bool:
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))
