import os
import shodan
from dotenv import load_dotenv  
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.logger import get_logger
from core.severity import classify_port, get_mitre

# ranges de IP conhecidos de CDNs principais
CDN_RANGES = [
    # Cloudflare
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
    "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.",
    # AWS CloudFront
    "13.224.", "13.225.", "13.226.", "13.227.", "13.228.", "13.229.",
    # Fastly
    "151.101."
]

CDN_NAMES = {
    "104." : "Cloudflare",
    "172.6": "Cloudflare",
    "13.22": "AWS CloudFront",
    "151." : "Fastly",

}

def detect_cdn(ip: str) -> str | None:
    """
    Verifica se o IP pertence a uma CDN conhecida.
    Retorna o nome da CDN ou NONE se não for CDN.
    """
    for prefix in CDN_RANGES:
        if ip.startswith(prefix):
            for key, name in CDN_NAMES.items():
                if ip.startswith(key):
                    return name
            return "CDN desconhecida"
    return None

load_dotenv()
logger = get_logger(__name__)


def get_client() -> shodan.Shodan:
    """
    Inicializa cliente Shodan com API key do .env
    """
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        raise ValueError("SHODAN_API_KEY não encontrada no .env")
    return shodan.Shodan(api_key)


def search_host(ip: str) -> dict:
    """
    Busca informações de um IP específico no Shodan.
    Retorna portas abertas, serviços e banners.
    """
    logger.info(f"[shodan] Buscando IP: {ip}")
    client = get_client()

    try:
        from core.retry import with_retry
        host = with_retry(lambda: client.host(ip))

        # processa cada serviço encontrado
        services = []
        for item in host.get("data", []):
            port = item.get("port")
            classification = classify_port(port)

            # contexto de ataque baseado na porta
            attack_type = _get_attack_type(port)
            mitre = get_mitre(attack_type) if attack_type else {}

            service = {
                "port"        : port,
                "protocol"    : item.get("transport", "tcp"),
                "service"     : item.get("product", "desconhecido"),
                "version"     : item.get("version", ""),
                "banner"      : item.get("data", "")[:800],  # Aumenta para capturar mais contexto
                "severity"    : classification["severity"],
                "description" : classification["description"],
                "mitre"       : mitre,
            }
            services.append(service)
            logger.warning(
                f"[shodan] Porta {port} — {classification['severity']} — {classification['description']}"
            )

        result = {
            "ip"           : ip,
            "organization" : host.get("org", "desconhecido"),
            "country"      : host.get("country_name", "desconhecido"),
            "city"         : host.get("city", "desconhecido"),
            "os"           : host.get("os", "desconhecido"),
            "hostnames"    : host.get("hostnames", []),
            "open_ports"   : [s["port"] for s in services],
            "services"     : services,
            "vulns"        : list(host.get("vulns", {}).keys()),
            "total_ports"  : len(services),
        }

        logger.info(f"[shodan] {len(services)} serviços encontrados em {ip}")
        return result

    except shodan.APIError as e:
        logger.error(f"[shodan] Erro na API: {str(e)}")
        return {"error": str(e), "ip": ip}


def search_domain(domain: str) -> dict:
    """
    Resolve IPs de um domínio e busca cada um no Shodan.
    """
    logger.info(f"[shodan] Resolvendo domínio: {domain}")
    client = get_client()

    try:
        # busca IPs associados ao domínio
        dns_result = with_retry(lambda: client.dns.resolve([domain]))       
        ip = dns_result.get(domain)

        if not ip:
            return {"error": f"Não foi possível resolver {domain}", "domain": domain}

        logger.info(f"[shodan] {domain} → {ip}")
        host_data = search_host(ip)
        host_data["domain"] = domain
        return host_data

    except shodan.APIError as e:
        logger.error(f"[shodan] Erro ao resolver domínio: {str(e)}")
        return {"error": str(e), "domain": domain}


def _get_attack_type(port: int) -> str:
    """
    Mapeia porta para tipo de ataque para busca no MITRE.
    """
    db_ports  = {1433, 3306, 5432, 9200, 27017, 6379}
    rdp_ports = {3389}
    ssh_ports = {22}
    ftp_ports = {21}
    smb_ports = {445, 139}

    if port in db_ports  : return "database_exposed"
    if port in rdp_ports : return "rdp_exposed"
    if port in ssh_ports : return "ssh_exposed"
    if port in ftp_ports : return "ftp_exposed"
    if port in smb_ports : return "smb_exposed"
    return ""


def run(target: str) -> dict:
    """
    Função principal. Detecta automaticamente se é IP ou domínio.
    """
    import re
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    
    if ip_pattern.match(target):
        cdn = detect_cdn(target)
        if cdn:
            logger.warning(
                f"[shodan] IP {target} pertence a {cdn}. "
                f"Dados do Shodan refletem a CDN, não o servidor de origem."
            )
        return search_host(target)
    else:
        return search_domain(target)