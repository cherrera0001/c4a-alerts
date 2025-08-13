"""
src/core/event_bus.py
Sistema de eventos para comunicación asíncrona entre componentes
"""
import asyncio
import logging
from typing import Dict, List, Callable, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import json


class EventType(Enum):
    """Tipos de eventos del sistema"""
    ALERT_COLLECTED = "alert.collected"
    ALERT_ENRICHED = "alert.enriched"
    ALERT_SCORED = "alert.scored"
    ALERT_PROCESSED = "alert.processed"
    ALERT_NOTIFIED = "alert.notified"
    ALERT_FAILED = "alert.failed"
    SOURCE_STARTED = "source.started"
    SOURCE_COMPLETED = "source.completed"
    SOURCE_FAILED = "source.failed"
    SYSTEM_HEALTH = "system.health"
    METRICS_UPDATED = "metrics.updated"


@dataclass
class Event:
    """Evento base del sistema"""
    type: EventType
    data: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    correlation_id: Optional[str] = None
    source: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte el evento a diccionario para serialización"""
        return {
            'type': self.type.value,
            'data': self.data,
            'timestamp': self.timestamp.isoformat(),
            'correlation_id': self.correlation_id,
            'source': self.source,
            'metadata': self.metadata
        }
    
    def to_json(self) -> str:
        """Convierte el evento a JSON"""
        return json.dumps(self.to_dict(), default=str)


class EventHandler:
    """Wrapper para manejadores de eventos con metadatos"""
    
    def __init__(self, handler: Callable, priority: int = 0, retry_count: int = 0):
        self.handler = handler
        self.priority = priority
        self.retry_count = retry_count
        self.call_count = 0
        self.error_count = 0
        self.last_error: Optional[Exception] = None
    
    async def __call__(self, event: Event) -> Any:
        """Ejecuta el handler"""
        try:
            self.call_count += 1
            result = await self.handler(event)
            return result
        except Exception as e:
            self.error_count += 1
            self.last_error = e
            raise


class EventBus:
    """Bus de eventos para comunicación asíncrona entre componentes"""
    
    def __init__(self, max_retries: int = 3, retry_delay: float = 1.0):
        self._subscribers: Dict[EventType, List[EventHandler]] = {}
        self._event_history: List[Event] = []
        self._max_history = 1000
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._logger = logging.getLogger(__name__)
        self._stats = {
            'events_published': 0,
            'events_processed': 0,
            'events_failed': 0,
            'handlers_executed': 0,
            'handlers_failed': 0
        }
    
    def subscribe(self, 
                  event_type: EventType, 
                  handler: Callable, 
                  priority: int = 0) -> EventHandler:
        """
        Suscribe un handler a un tipo de evento
        
        Args:
            event_type: Tipo de evento
            handler: Función handler (debe ser async)
            priority: Prioridad (mayor número = mayor prioridad)
            
        Returns:
            EventHandler: Handler registrado
        """
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        
        event_handler = EventHandler(handler, priority)
        self._subscribers[event_type].append(event_handler)
        
        # Ordenar por prioridad (mayor prioridad primero)
        self._subscribers[event_type].sort(key=lambda h: h.priority, reverse=True)
        
        self._logger.info(f"Subscribed handler to {event_type.value} with priority {priority}")
        return event_handler
    
    def unsubscribe(self, event_type: EventType, handler: EventHandler):
        """Desuscribe un handler"""
        if event_type in self._subscribers:
            try:
                self._subscribers[event_type].remove(handler)
                self._logger.info(f"Unsubscribed handler from {event_type.value}")
            except ValueError:
                self._logger.warning(f"Handler not found for {event_type.value}")
    
    async def publish(self, 
                      event_type: EventType, 
                      data: Dict[str, Any],
                      correlation_id: Optional[str] = None,
                      source: Optional[str] = None,
                      metadata: Optional[Dict[str, Any]] = None) -> List[Any]:
        """
        Publica un evento a todos los subscribers
        
        Args:
            event_type: Tipo de evento
            data: Datos del evento
            correlation_id: ID de correlación para tracking
            source: Fuente del evento
            metadata: Metadatos adicionales
            
        Returns:
            List de resultados de los handlers
        """
        event = Event(
            type=event_type,
            data=data,
            correlation_id=correlation_id,
            source=source,
            metadata=metadata or {}
        )
        
        return await self.publish_event(event)
    
    async def publish_event(self, event: Event) -> List[Any]:
        """
        Publica un evento específico
        
        Args:
            event: Evento a publicar
            
        Returns:
            List de resultados de los handlers
        """
        self._stats['events_published'] += 1
        
        # Agregar a historial
        self._add_to_history(event)
        
        if event.type not in self._subscribers:
            self._logger.debug(f"No subscribers for event type {event.type.value}")
            return []
        
        handlers = self._subscribers[event.type]
        self._logger.debug(f"Publishing {event.type.value} to {len(handlers)} handlers")
        
        results = []
        tasks = []
        
        # Crear tareas para todos los handlers
        for handler in handlers:
            task = asyncio.create_task(
                self._execute_handler_with_retry(handler, event)
            )
            tasks.append(task)
        
        # Ejecutar todos los handlers en paralelo
        if tasks:
            task_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(task_results):
                if isinstance(result, Exception):
                    self._stats['handlers_failed'] += 1
                    self._logger.error(
                        f"Handler {i} failed for {event.type.value}: {result}",
                        extra={'correlation_id': event.correlation_id}
                    )
                else:
                    self._stats['handlers_executed'] += 1
                    results.append(result)
        
        self._stats['events_processed'] += 1
        return results
    
    async def _execute_handler_with_retry(self, 
                                          handler: EventHandler, 
                                          event: Event) -> Any:
        """
        Ejecuta un handler con reintentos
        
        Args:
            handler: Handler a ejecutar
            event: Evento a procesar
            
        Returns:
            Resultado del handler
        """
        last_exception = None
        
        for attempt in range(self._max_retries + 1):
            try:
                result = await handler(event)
                if attempt > 0:
                    self._logger.info(
                        f"Handler succeeded on attempt {attempt + 1}",
                        extra={'correlation_id': event.correlation_id}
                    )
                return result
                
            except Exception as e:
                last_exception = e
                self._logger.warning(
                    f"Handler failed on attempt {attempt + 1}: {e}",
                    extra={'correlation_id': event.correlation_id}
                )
                
                if attempt < self._max_retries:
                    delay = self._retry_delay * (2 ** attempt)  # Exponential backoff
                    await asyncio.sleep(delay)
        
        # Si llegamos aquí, todos los reintentos fallaron
        self._logger.error(
            f"Handler failed after {self._max_retries + 1} attempts",
            extra={'correlation_id': event.correlation_id}
        )
        raise last_exception
    
    def _add_to_history(self, event: Event):
        """Agrega evento al historial"""
        self._event_history.append(event)
        
        # Mantener solo los últimos N eventos
        if len(self._event_history) > self._max_history:
            self._event_history = self._event_history[-self._max_history:]
    
    def get_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas del bus de eventos"""
        handler_stats = {}
        
        for event_type, handlers in self._subscribers.items():
            handler_stats[event_type.value] = {
                'handler_count': len(handlers),
                'total_calls': sum(h.call_count for h in handlers),
                'total_errors': sum(h.error_count for h in handlers)
            }
        
        return {
            **self._stats,
            'handler_stats': handler_stats,
            'event_history_size': len(self._event_history),
            'subscription_count': sum(len(handlers) for handlers in self._subscribers.values())
        }
    
    def get_recent_events(self, limit: int = 100) -> List[Event]:
        """Obtiene eventos recientes"""
        return self._event_history[-limit:]
    
    def clear_history(self):
        """Limpia el historial de eventos"""
        self._event_history.clear()
        self._logger.info("Event history cleared")
    
    async def health_check(self) -> Dict[str, Any]:
        """Realiza un health check del bus de eventos"""
        test_event = Event(
            type=EventType.SYSTEM_HEALTH,
            data={'test': True}
        )
        
        start_time = datetime.now()
        
        try:
            await self.publish_event(test_event)
            latency = (datetime.now() - start_time).total_seconds()
            
            return {
                'status': 'healthy',
                'latency_seconds': latency,
                'stats': self.get_stats()
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e),
                'stats': self.get_stats()
            }


# Instancia global del bus de eventos
event_bus = EventBus()


# Decorador para facilitar la suscripción
def subscribe_to(event_type: EventType, priority: int = 0):
    """
    Decorador para suscribir funciones a eventos
    
    Usage:
        @subscribe_to(EventType.ALERT_COLLECTED)
        async def handle_alert(event: Event):
            print(f"Received alert: {event.data}")
    """
    def decorator(func):
        event_bus.subscribe(event_type, func, priority)
        return func
    return decorator
