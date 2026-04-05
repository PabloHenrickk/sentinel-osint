import time
from core.logger import get_logger

logger = get_logger(__name__)


def with_retry(func, retries: int = 3, delay: float = 2.0):
    """
    Executa uma função com retry automático e backoff exponencial.

    Parâmetros:
        func    → função sem argumentos (use lambda se precisar passar args)
        retries → número máximo de tentativas
        delay   → tempo base em segundos entre tentativas

    Exemplo de uso:
        result = with_retry(lambda: client.host(ip))

    Backoff:
        tentativa 1 → espera 2s
        tentativa 2 → espera 4s
        tentativa 3 → desiste e lança exceção
    """
    for attempt in range(retries):
        try:
            return func()

        except Exception as e:
            is_last = attempt == retries - 1

            if is_last:
                logger.error(f"[retry] Falhou após {retries} tentativas: {str(e)}")
                raise

            wait = delay * (2 ** attempt)
            logger.warning(
                f"[retry] Tentativa {attempt + 1}/{retries} falhou: {str(e)}. "
                f"Aguardando {wait}s antes de tentar novamente..."
            )
            time.sleep(wait)