from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "PacketArena API"
    DB_DSN: str = "postgresql+psycopg://packetarena:packetarena@127.0.0.1:5432/packetarena"

    # 로컬 eve.json (원격 미사용 시)
    EVE_PATH: str = "/var/log/suricata/eve.json"

    # 원격 Suricata SSH 기본값 (원격 tail 시 사용)
    SSH_USER: str = "pa"                                # 원격 사용자
    SSH_KEYFILE: str = f"/home/pa/.ssh/id_ed25519"      # 백엔드 VM의 개인키
    REMOTE_EVE_PATH: str = "/var/log/suricata/eve.json" # 원격 센서의 eve.json

    PCAP_DIR: str = "/opt/packetarena/pcaps"

settings = Settings()

