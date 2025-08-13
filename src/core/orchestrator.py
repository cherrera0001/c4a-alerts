"""
src/core/orchestrator.py
Orchestrator mejorado con procesamiento asíncrono y sistema de eventos
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
import asyncio
import logging


class AlertPriority(Enum):
    CRITICAL = "critical"
    HIGH = "high" 
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ProcessingStatus(Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"


@dataclass
class AlertEvent:
    """Evento de alerta estandardizado"""
    id: str
    source: str
    raw_data: Dict[str, Any]
    timestamp: float
    priority: AlertPriority
    status: ProcessingStatus = ProcessingStatus.PENDING
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class EventBus:
    """Bus de eventos para comunicación asíncrona entre componentes"""
    
    def __init__(self):
        self._subscribers: Dict[str, List[callable]] = {}
        self._logger = logging.getLogger(__name__)
    
    def subscribe(self, event_type: str, handler: callable):
        """Suscribe un handler a un tipo de evento"""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(handler)
    
    async def publish(self, event_type: str, event: AlertEvent):
        """Publica un evento a todos los subscribers"""
        if event_type not in self._subscribers:
            return
        
        tasks = []
        for handler in self._subscribers[event_type]:
            task = asyncio.create_task(handler(event))
            tasks.append(task)
        
        # Ejecutar todos los handlers en paralelo
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    self._logger.error(f"Error in handler {i}: {result}")


class BaseProcessor(ABC):
    """Clase base para todos los procesadores"""
    
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self._logger = logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    async def process(self, event: AlertEvent) -> AlertEvent:
        """Procesa un evento de alerta"""
        pass
    
    @abstractmethod
    def get_processor_name(self) -> str:
        """Retorna el nombre del procesador"""
        pass


class EnrichmentProcessor(BaseProcessor):
    """Procesador de enriquecimiento de datos"""
    
    async def process(self, event: AlertEvent) -> AlertEvent:
        """Enriquece el evento con información adicional"""
        self._logger.info(f"Enriching event {event.id}")
        
        # Simular enriquecimiento (OSINT, geolocalización, etc.)
        event.metadata.update({
            'enriched_at': asyncio.get_event_loop().time(),
            'enrichment_source': 'multiple',
            'confidence_score': 0.85
        })
        
        return event
    
    def get_processor_name(self) -> str:
        return "enrichment"


class ScoringProcessor(BaseProcessor):
    """Procesador de scoring de amenazas"""
    
    async def process(self, event: AlertEvent) -> AlertEvent:
        """Calcula el score de la amenaza"""
        self._logger.info(f"Scoring event {event.id}")
        
        # Lógica de scoring basada en múltiples factores
        base_score = self._calculate_base_score(event)
        temporal_score = self._calculate_temporal_score(event)
        environmental_score = self._calculate_environmental_score(event)
        
        final_score = (base_score * 0.6 + temporal_score * 0.3 + environmental_score * 0.1)
        
        event.metadata.update({
            'threat_score': final_score,
            'base_score': base_score,
            'temporal_score': temporal_score,
            'environmental_score': environmental_score,
            'scored_at': asyncio.get_event_loop().time()
        })
        
        # Actualizar prioridad basada en score
        if final_score >= 9.0:
            event.priority = AlertPriority.CRITICAL
        elif final_score >= 7.0:
            event.priority = AlertPriority.HIGH
        elif final_score >= 5.0:
            event.priority = AlertPriority.MEDIUM
        else:
            event.priority = AlertPriority.LOW
            
        return event
    
    def _calculate_base_score(self, event: AlertEvent) -> float:
        """Calcula score base (CVSS, severity, etc.)"""
        # Implementar lógica de scoring base
        return 7.5
    
    def _calculate_temporal_score(self, event: AlertEvent) -> float:
        """Calcula score temporal (recencia, tendencias)"""
        # Implementar lógica temporal
        return 8.0
    
    def _calculate_environmental_score(self, event: AlertEvent) -> float:
        """Calcula score ambiental (contexto organizacional)"""
        # Implementar lógica ambiental
        return 6.0
    
    def get_processor_name(self) -> str:
        return "scoring"


class ImprovedOrchestrator:
    """Orchestrator mejorado con procesamiento asíncrono"""
    
    def __init__(self):
        self.event_bus = EventBus()
        self.processors: List[BaseProcessor] = []
        self._logger = logging.getLogger(__name__)
        self._setup_processors()
        self._setup_event_handlers()
    
    def _setup_processors(self):
        """Configura los procesadores disponibles"""
        self.processors = [
            EnrichmentProcessor(self.event_bus),
            ScoringProcessor(self.event_bus)
        ]
    
    def _setup_event_handlers(self):
        """Configura los manejadores de eventos"""
        self.event_bus.subscribe('alert.collected', self._handle_collected_alert)
        self.event_bus.subscribe('alert.processed', self._handle_processed_alert)
        self.event_bus.subscribe('alert.enriched', self._handle_enriched_alert)
        self.event_bus.subscribe('alert.scored', self._handle_scored_alert)
    
    async def process_alerts(self, raw_alerts: List[Dict[str, Any]]) -> List[AlertEvent]:
        """Procesa múltiples alertas en paralelo"""
        events = []
        
        # Crear eventos
        for raw_alert in raw_alerts:
            event = AlertEvent(
                id=raw_alert.get('id', ''),
                source=raw_alert.get('source', ''),
                raw_data=raw_alert,
                timestamp=asyncio.get_event_loop().time(),
                priority=AlertPriority.MEDIUM
            )
            events.append(event)
        
        # Procesar en paralelo
        tasks = [self._process_single_alert(event) for event in events]
        processed_events = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filtrar errores
        successful_events = [
            event for event in processed_events 
            if isinstance(event, AlertEvent)
        ]
        
        return successful_events
    
    async def _process_single_alert(self, event: AlertEvent) -> AlertEvent:
        """Procesa una sola alerta a través de todos los procesadores"""
        try:
            event.status = ProcessingStatus.PROCESSING
            await self.event_bus.publish('alert.collected', event)
            
            # Procesar secuencialmente a través de cada procesador
            for processor in self.processors:
                event = await processor.process(event)
                await self.event_bus.publish(f'alert.{processor.get_processor_name()}', event)
            
            event.status = ProcessingStatus.COMPLETED
            await self.event_bus.publish('alert.processed', event)
            
            return event
            
        except Exception as e:
            self._logger.error(f"Error processing alert {event.id}: {e}")
            event.status = ProcessingStatus.FAILED
            event.metadata['error'] = str(e)
            return event
    
    async def _handle_collected_alert(self, event: AlertEvent):
        """Maneja alertas recién recolectadas"""
        self._logger.info(f"Alert collected: {event.id}")
    
    async def _handle_processed_alert(self, event: AlertEvent):
        """Maneja alertas completamente procesadas"""
        self._logger.info(f"Alert processed: {event.id} with priority {event.priority.value}")
    
    async def _handle_enriched_alert(self, event: AlertEvent):
        """Maneja alertas enriquecidas"""
        self._logger.info(f"Alert enriched: {event.id}")
    
    async def _handle_scored_alert(self, event: AlertEvent):
        """Maneja alertas con score calculado"""
        score = event.metadata.get('threat_score', 0)
        self._logger.info(f"Alert scored: {event.id} - Score: {score}")
