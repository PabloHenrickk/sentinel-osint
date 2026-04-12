"""
base.py — Contrato base da provider layer do Sentinel OSINT

Todo provider deve:
  1. Herdar de BaseProvider
  2. Implementar _fetch() com a lógica de coleta
  3. Retornar sempre NormalizedEntity ou lista delas
  4. Nunca propagar exceções — usar safe_query()

Modelo unificado garante que qualquer provider novo
encaixa no grafo e no ai_analyst sem adaptação.
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.logger import get_logger

logger = get_logger(__name__)


# ── Modelo de entidade unificado ──────────────────────────────

@dataclass
class NormalizedEntity:
    """
    Unidade atômica de dado no Sentinel OSINT.
    Todo provider retorna NormalizedEntity — nunca dict cru.

    entity_type : empresa | pessoa | dominio | ip | email | contrato
    source      : brasilapi | receitaws | transparencia | shodan | ...
    data_type   : cnpj | razao_social | socio | ip | porta | contrato | sancao
    value       : o dado em si (string, número ou dict simples)
    metadata    : campos auxiliares sem schema fixo
    confidence  : 0.0 a 1.0 — quão confiável é a fonte
    relations   : lista de (tipo_relação, entidade_alvo) para o grafo
    """
    entity_type : str
    source      : str
    data_type   : str
    value       : Any
    metadata    : dict                  = field(default_factory=dict)
    confidence  : float                 = 1.0
    relations   : list[tuple[str, str]] = field(default_factory=list)
    collected_at: str                   = field(
        default_factory=lambda: datetime.now().isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "entity_type" : self.entity_type,
            "source"      : self.source,
            "data_type"   : self.data_type,
            "value"       : self.value,
            "metadata"    : self.metadata,
            "confidence"  : self.confidence,
            "relations"   : self.relations,
            "collected_at": self.collected_at,
        }


# ── Resultado de provider ─────────────────────────────────────

@dataclass
class ProviderResult:
    """
    Envelope de retorno de qualquer provider.
    Sempre retornado — mesmo em falha total.

    success   : False se todas as fontes falharam
    entities  : lista de NormalizedEntity coletadas
    errors    : erros por fonte (nunca suprimidos silenciosamente)
    source    : nome do provider que gerou o resultado
    """
    success : bool
    entities: list[NormalizedEntity]
    errors  : list[str]
    source  : str
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "success" : self.success,
            "source"  : self.source,
            "entities": [e.to_dict() for e in self.entities],
            "errors"  : self.errors,
            "metadata": self.metadata,
        }

    def merge(self, other: "ProviderResult") -> "ProviderResult":
        """Combina dois resultados — útil para consolidar fontes."""
        return ProviderResult(
            success  = self.success or other.success,
            entities = self.entities + other.entities,
            errors   = self.errors   + other.errors,
            source   = f"{self.source}+{other.source}",
            metadata = {**self.metadata, **other.metadata},
        )


# ── safe_query — wrapper de resiliência ──────────────────────

def safe_query(
    func,
    *args,
    retries    : int   = 2,
    delay      : float = 1.0,
    source_name: str   = "unknown",
    **kwargs,
) -> Optional[Any]:
    """
    Executa func(*args, **kwargs) com retry e falha silenciosa.
    Nunca propaga exceção — retorna None em falha total.

    Por que retries=2 e não mais:
    APIs públicas gratuitas têm rate limit baixo.
    Mais de 2 retries em falha real só piora a situação.
    """
    last_error: Optional[Exception] = None

    for attempt in range(1, retries + 1):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            last_error = e
            logger.warning(
                f"[{source_name}] Tentativa {attempt}/{retries} falhou: {e}"
            )
            if attempt < retries:
                time.sleep(delay * attempt)   # backoff linear simples

    logger.error(f"[{source_name}] Todas as tentativas falharam: {last_error}")
    return None


# ── BaseProvider — contrato abstrato ─────────────────────────

class BaseProvider(ABC):
    """
    Todo provider herda daqui.
    Garante interface uniforme independente da fonte.

    O método run() é o único ponto de entrada externo.
    _fetch() é onde a lógica específica de cada provider vive.
    _normalize() transforma o dado bruto em NormalizedEntity.
    """

    name      : str   = "base"
    confidence: float = 1.0   # override por provider

    def run(self, *args, **kwargs) -> ProviderResult:
        """
        Entry point público — nunca levanta exceção.
        Chama _fetch() e normaliza o resultado.
        """
        errors  : list[str]             = []
        entities: list[NormalizedEntity] = []

        try:
            raw = self._fetch(*args, **kwargs)
            if raw is not None:
                normalized = self._normalize(raw)
                if isinstance(normalized, list):
                    entities = normalized
                elif normalized is not None:
                    entities = [normalized]
        except Exception as e:
            msg = f"[{self.name}] Erro em _fetch/_normalize: {e}"
            errors.append(msg)
            logger.error(msg)

        return ProviderResult(
            success  = len(entities) > 0,
            entities = entities,
            errors   = errors,
            source   = self.name,
        )

    @abstractmethod
    def _fetch(self, *args, **kwargs) -> Any:
        """Lógica de coleta específica do provider."""
        ...

    @abstractmethod
    def _normalize(self, raw: Any) -> list[NormalizedEntity]:
        """Transforma dado bruto em lista de NormalizedEntity."""
        ...


# ── Helpers de normalização ───────────────────────────────────

def clamp_confidence(value: float) -> float:
    """Garante que confidence fique entre 0.0 e 1.0."""
    return max(0.0, min(1.0, value))


def build_relation(
    relation_type: str,
    target       : str,
) -> tuple[str, str]:
    """
    Cria uma tupla de relação para o grafo.

    Exemplos:
        build_relation("tem_socio",    "João Silva")
        build_relation("tem_dominio",  "empresa.com.br")
        build_relation("resolve_para", "192.168.1.1")
    """
    return (relation_type, target)