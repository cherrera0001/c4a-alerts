"""
Database connection and operations module for C4A Alerts
"""
import logging
from typing import Optional, Dict, Any
from supabase import create_client, Client
from src.config import SUPABASE_CONFIG, DB_CONFIG

class DatabaseManager:
    _instance: Optional['DatabaseManager'] = None
    _client: Optional[Client] = None

    def __new__(cls) -> 'DatabaseManager':
        if cls._instance is None:
            cls._instance = super(DatabaseManager, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._client:
            try:
                self._client = create_client(
                    SUPABASE_CONFIG["url"],
                    SUPABASE_CONFIG["anon_key"]
                )
                logging.info("✅ Conexión a Supabase establecida correctamente")
            except Exception as e:
                logging.error(f"❌ Error al conectar con Supabase: {e}")
                raise

    @property
    def client(self) -> Client:
        if not self._client:
            raise RuntimeError("Cliente Supabase no inicializado")
        return self._client

    def execute_query(self, query: str, values: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Ejecuta una consulta SQL personalizada
        """
        try:
            result = self.client.rpc(
                'execute_sql',
                {'query': query, 'values': values or {}}
            ).execute()
            return result.data
        except Exception as e:
            logging.error(f"❌ Error ejecutando consulta: {e}")
            raise

    def get_alerts(self, limit: int = 100) -> list:
        """
        Obtiene las últimas alertas almacenadas
        """
        try:
            result = self.client.table('alerts').select('*').limit(limit).execute()
            return result.data
        except Exception as e:
            logging.error(f"❌ Error obteniendo alertas: {e}")
            return []

    def save_alert(self, alert_data: Dict[str, Any]) -> bool:
        """
        Guarda una nueva alerta en la base de datos
        """
        try:
            result = self.client.table('alerts').insert(alert_data).execute()
            return bool(result.data)
        except Exception as e:
            logging.error(f"❌ Error guardando alerta: {e}")
            return False

# Ejemplo de uso:
# db = DatabaseManager()
# alerts = db.get_alerts(limit=10)