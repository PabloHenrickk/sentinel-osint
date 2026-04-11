from enum import Enum


class Severity(Enum):
    CRITICAL = "CRÍTICO"
    HIGH     = "ALTO"
    MEDIUM   = "MÉDIO"
    LOW      = "BAIXO"
    INFO     = "INFO"


# pontuação mínima para cada nível
SEVERITY_THRESHOLDS = {
    Severity.CRITICAL : 90,
    Severity.HIGH     : 70,
    Severity.MEDIUM   : 40,
    Severity.LOW      : 20,
    Severity.INFO     : 0,
}

# portas conhecidas e seu risco associado
RISKY_PORTS = {
    21   : (Severity.HIGH,     "FTP — transferência sem criptografia"),
    22   : (Severity.MEDIUM,   "SSH — verificar autenticação por senha"),
    23   : (Severity.CRITICAL, "Telnet — protocolo sem criptografia"),
    25   : (Severity.MEDIUM,   "SMTP — verificar relay aberto"),
    80   : (Severity.LOW,      "HTTP — tráfego sem criptografia"),
    443  : (Severity.INFO,     "HTTPS — padrão seguro"),
    445  : (Severity.HIGH,     "SMB — vulnerável a EternalBlue/WannaCry"),
    1433 : (Severity.CRITICAL, "MSSQL — banco exposto publicamente"),
    3306 : (Severity.CRITICAL, "MySQL — banco exposto publicamente"),
    3389 : (Severity.CRITICAL, "RDP — acesso remoto exposto"),
    5432 : (Severity.CRITICAL, "PostgreSQL — banco exposto publicamente"),
    6379 : (Severity.HIGH,     "Redis — frequentemente sem autenticação"),
    8080 : (Severity.LOW,      "HTTP alternativo — verificar serviço"),
    8443 : (Severity.LOW,      "HTTPS alternativo"),
    9200 : (Severity.CRITICAL, "Elasticsearch — banco exposto publicamente"),
    9929 : (Severity.MEDIUM,   "nping-echo — ferramenta de diagnóstico Nmap exposta; verificar se intencional"),
    27017: (Severity.CRITICAL, "MongoDB — frequentemente sem autenticação"),
    31337: (Severity.HIGH,     "Back Orifice / backdoor histórico — porta associada a RATs e C2; investigar imediatamente"),
}

# técnicas MITRE ATT&CK por tipo de exposição
MITRE_MAP = {
    "database_exposed"  : ("T1190",     "Exploit Public-Facing Application"),
    "rdp_exposed"       : ("T1021.001", "Remote Services: RDP"),
    "ssh_exposed"       : ("T1021.004", "Remote Services: SSH"),
    "ftp_exposed"       : ("T1071.002", "Application Layer Protocol: FTP"),
    "smb_exposed"       : ("T1021.002", "Remote Services: SMB"),
    "default_creds"     : ("T1078.001", "Valid Accounts: Default Accounts"),
    "data_exposure"     : ("T1213",     "Data from Information Repositories"),
    "non_standard_port" : ("T1571",     "Non-Standard Port"),
    "backdoor_port"     : ("T1571",     "Non-Standard Port — backdoor histórico ou C2"),
}


def classify_port(port: int) -> dict:
    """
    Classifica uma porta aberta por severidade e contexto.
    Retorna dicionário com severidade, descrição e técnica MITRE.
    """
    if port in RISKY_PORTS:
        severity, description = RISKY_PORTS[port]

        # Portas de backdoor recebem mapeamento MITRE explícito
        if port == 31337:
            mitre = MITRE_MAP["backdoor_port"]
            return {
                "port"        : port,
                "severity"    : severity.value,
                "description" : description,
                "mitre_id"    : mitre[0],
                "mitre_name"  : mitre[1],
                "note"        : "31337 = 'eleet' em leet speak — uso comum em C2 e malware moderno",
            }

        if port == 9929:
            mitre = MITRE_MAP["non_standard_port"]
            return {
                "port"        : port,
                "severity"    : severity.value,
                "description" : description,
                "mitre_id"    : mitre[0],
                "mitre_name"  : mitre[1],
            }

        return {
            "port"       : port,
            "severity"   : severity.value,
            "description": description,
        }

    return {
        "port"       : port,
        "severity"   : Severity.LOW.value,
        "description": f"Porta {port} aberta — serviço não mapeado",
    }


def get_severity_from_score(score: int) -> str:
    """
    Converte score numérico em nível de severidade.
    Usado pelo validator para classificar o resultado geral.
    """
    for severity, threshold in SEVERITY_THRESHOLDS.items():
        if score >= threshold:
            return severity.value
    return Severity.INFO.value


def get_mitre(attack_type: str) -> dict:
    """
    Retorna técnica MITRE ATT&CK para um tipo de ataque.
    """
    if attack_type in MITRE_MAP:
        technique_id, technique_name = MITRE_MAP[attack_type]
        return {
            "technique_id"  : technique_id,
            "technique_name": technique_name,
            "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}",
        }
    return {}