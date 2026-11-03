# Plan de Acción de Seguridad - Investigación de Amenazas SOC L2

## Resumen Ejecutivo (1-2 Páginas)

### Hallazgos Principales
- **Incidente**: INC-1 (Crítico, 100/100) - Combinación de tácticas múltiples
- **Afectados**: 2 hosts (SRV-APP01, SRV-DB01), 1 usuario (admin)
- **Alcance**: Actividades desde IP 10.0.2.15 (interna) e 185.220.101.45 (externa)
- **Evidencia**: Múltiples Log_IDs asociados con autenticación fallida y ejecución exitosa

### Estado del Incidente
| SEVERIDAD | CONFIDENCE | ESTADO               | ACTIVO               | ACCIÓN                          |
|-----------|------------|----------------------|----------------------|---------------------------------|
| Crítico   | Alta       | Activo – requiere contención | SRV-APP01, SRV-DB01 | Contención inmediata y escalar a IR/T3 |

### Acciones Inmediatas Requeridas
1. **Contención**: Aislar hosts SRV-APP01 y SRV-DB01 de la red
2. **Bloqueo**: Bloquear IP externa 185.220.101.45 en firewall
3. **Reset**: Cambiar credenciales del usuario admin inmediatamente
4. **Investigación**: Validar inicio de sesión exitoso en SRV-APP01/SRV-DB01

### Gaps y Siguientes Pasos
- Validación humana pendiente de todos los hallazgos
- Monitoreo adicional necesario para actividad post-compromiso
- Investigación forense completa del timeline completo de eventos
- Revisar controles de acceso para prevenir movimiento lateral futuro

## Plan de Acción Técnico Detallado

### 1. Assessment Técnico y Confianza
**Nivel de certeza del analista**: Alta (riesgo Crítico, 100/100)

### 2. Timeline de Eventos
- **Rango**: 2025-03-15 08:30 → 2025-03-15 12:45 (Zona no indicada)
- **Total de eventos analizados**: 29
- **Hosts afectados**: SRV-APP01, SRV-DB01
- **Usuarios involucrados**: admin

### 3. Hallazgos Detallados

#### Hallazgos y Evidencia (IDs, Riesgo, Hallazgo, MITRE, Evidencia)

**F-01** [Crítico] Fuerza bruta desde 10.0.2.15 (T1110.003: Credential Access)
- **Evidencia**: Log_IDs: [L001, L002, L003, L004, L005, L006, L007, L008, L009]
- **IOCs**: IP 10.0.2.15 (interna)
- **Vulnerabilidad**: Credenciales débiles

**F-02** [Crítico] Inicio de sesión exitoso tras 9 fallos (10.0.2.15 → admin@SRV-APP01) (T1078: Valid Accounts)
- **Evidencia**: Log_IDs: [L010, L011, L012, L013]
- **IOCs**: IP 10.0.2.15, usuario admin, host SRV-APP01
- **Vulnerabilidad**: Credencial adivinada

**F-03** [Alto] Comando PowerShell ofuscado detectado en SRV-DB01 (T1059.001: Execution)
- **Evidencia**: Log_IDs: [L014, L015, L016]
- **IOCs**: Host SRV-DB01
- **Vulnerabilidad**: Ejecución de código

### 4. KPIs de la Investigación
| Eventos | Hosts | Usuarios | Rango               | Zona              |
|---------|-------|----------|----------------------|-------------------|
| 29      | 2     | 1        | 2025-03-15 08:30 → 2025-03-15 12:45 | Zona no indicada |

### 5. Acciones Ejecutadas / Recomendadas
1. **Contención**: Aislar los hosts SRV-APP01 y SRV-DB01 y bloquear IPs externas
2. **Eradicación**: Deshabilitar y restablecer credenciales de admin
3. **Recuperación**: Restaurar desde estado conocido y monitorear 30 días
4. **Post-incidente**: Lecciones aprendidas y ajuste de reglas SIEM (NIST SP 800-61)

### 6. Gaps y Preguntas Pendientes
- Validar si el inicio de sesión en SRV-APP01/SRV-DB01 es legítimo
- Investigar uso de PowerShell ofuscado en SRV-DB01
- Verificar si la cuenta admin es una cuenta de servicio o usuario legítimo
- Confirmar cuando la actividad es una prueba vs ataque real

### 7. Riesgos de Continuar / No Continuar

**Riesgos de continuar sin contención**:
- Movimiento lateral a otros hosts corporativos
- Exfiltración de datos sensibles
- Compromiso persistente de los sistemas afectados
- Posible establecimiento de persistencia (tareas programadas, servicios)

**Riesgos de no actuar**:
- Exposición continua a la misma amenaza
- Posible compromiso de credenciales de administrador
- Riesgo de múltiplesintentos de autenticación exitosos
- Impacto potencial en servicios críticos (APP, DB)

## Consideraciones de Escalamiento

### Escalar a IR/T3 cuando:
1. **Validación humana** confirma los hallazgos
2. **Forensica** identifica herramientas de atacante
3. **Daño** confirma exfiltración o impacto en servicios críticos
4. **Contención** temporal no es suficiente

### Criterios de escalamiento:
- **Técnico**: Hallazgos confirmados en múltiples sistemas críticos
- **Negocio**: Impacto en servicios > 4 horas o pérdida de datos detectada
- **Legal**: Violación regulatoria o exposición de datos personales

## Monitoreo Requerido

### Durante Contención:
1. **Hosts aislados**: Monitorear tráfico saliente en SRV-APP01/SRV-DB01
2. **Bloqueo de IP**: Revisar logs para intentos de acceso desde 185.220.101.45
3. **Credenciales**: Monitorear intentos de login desde usuario admin

### Durante Recuperación:
1. **Ransomware**: Verificar cifrado de archivos en hosts afectados
2. **Persistencia**: Buscar tareas programadas, servicios, scripts de inicio
3. **Comando y Control**: Detectar comunicaciones C2 con servidores externos

### Post-incidente (30 días):
1. **Detección**: Monitorear actividad anómala desde IPs/host comprometidos
2. **Acceso**: Revisar logs de acceso y privilegios de usuario admin
3. **Secuencia**: Investigar cualquier actividad no usual para usuario admin

## Documentación Requerida

1. **Reporte de incidente completo**: PDF ejecutivo y técnico
2. **Evidencia forense**: Capturas de pantalla, logs, evidencia binaria
3. **Cronograma de contención**: Fechas y responsables de cada acción
4. **Lecciones aprendidas**: Mejoras de controles y recomendaciones

## Próximos Pasos Inmediatos

1. **Implementar acciones de contención** dentro de 1 hora
2. **Validar hallazgos** con personal técnico senior
3. **Escalar a IR/T3** si hallazgos confirmados
4. **Iniciar recuperación** después de contención completada
5. **Documentar todo** para reporte y cumplimiento legal

## Referencias

- NIST SP 800-61 Rev.2: Gestión de Incidentes de Seguridad
- MITRE ATT&CK Framework: Tácticas y Técnicas utilizadas
- Guías de investigación de SOC Nivel 2: Procedimientos estándar