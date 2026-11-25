# Informe de auditoría de liberación: ReservaLab

Curso: Aseguramiento de la Calidad de Software, Unidad 3, Clase 16.
Fecha: 23 de noviembre de 2026.
Alcance: flujo de reserva de laboratorio (usabilidad, accesibilidad WCAG 2.2 AA, confiabilidad y seguridad web).
Criterios: documento "Clase 16: Fundamentos teóricos". Las anclas (§, T, F, R) remiten a ese documento.
La prioridad de cada hallazgo se asigna con la matriz T11. Las capturas están en `evidencias/`. Este informe no contiene contraseñas ni tokens.

| Integrante | Correo institucional | Rol de auditoría |
|---|---|---|
| Daniel Sozoranga | dasozorangamo@uide.edu.ec | Usabilidad y accesibilidad |
| Ricardo Alvarez | rialvarezso@uide.edu.ec | Confiabilidad y seguridad |

Entorno auditado: Pendiente (URL o versión de ReservaLab). Las pruebas de seguridad se hicieron solo en el entorno autorizado (R8).
Herramientas: axe DevTools (axe-core 4.13.0), Lighthouse (versión pendiente), OWASP ZAP (versión pendiente), Postman (versión pendiente).

## 1. Veredicto: NO-GO

Hay seis hallazgos P1 abiertos: SEC-01 (inyección SQL crítica), SEC-02 (IDOR), A11Y-01 (botón Reservar no operable con teclado, criterio 2.1.1 nivel A), SRE-01 (presupuesto de error al 116.7 %, SLO incumplido), UX-01 (fecha interpretada mes/día, severidad 4) y UX-07 (horas en UTC que producen una reserva en horario equivocado, severidad 4). La regla R9 exige No-Go con un solo P1 abierto.

## 2. Resumen

| Prioridad | Cantidad | IDs |
|---|---|---|
| P1 | 6 | SEC-01, SEC-02, A11Y-01, SRE-01, UX-01, UX-07 |
| P2 | 18 | SEC-03, A11Y-02 a A11Y-13, SRE-02, UX-02 a UX-05 |
| P3 | 3 | SEC-04, UX-06, UX-08 |

A11Y-02, A11Y-03 y A11Y-04 vienen del escaneo de la página de práctica W3C BAD (axe: 45 problemas, Lighthouse: 56 antes y 84 después). El resto de A11Y viene del código de ReservaLab.
En cada prioridad el orden es: seguridad, accesibilidad nivel A, confiabilidad, usabilidad (T11).

## 3. Hallazgos P1 (bloqueantes)

| Hallazgo | Evidencia | Criterio violado | Severidad | Prioridad | Recomendación | Ancla |
| --- | --- | --- | --- | --- | --- | --- |
| **SEC-01** Inyección SQL en endpoint público | Pendiente: petición, payload y respuesta. Captura `evidencias/zap-sqli.png` | A03:2021 Injection (A05:2025), CWE-89 | Crítica | **P1** | Usar consultas parametrizadas, validar con lista permitida, usar cuenta de BD con privilegio mínimo y no mostrar errores internos | §4.4 |
| **SEC-02** IDOR en `/api/facturas/{id}` | `GET /api/facturas/552` con el token de la usuaria A devuelve 200 con datos del usuario B (se esperaba 403 o 404). Captura `evidencias/postman-idor.png` | A01:2021 Broken Access Control (A01:2025), CWE-639 | Alta | **P1** | Verificar en el servidor que el recurso pertenece al usuario (`WHERE id = ? AND owner_id = usuario_actual`) y denegar por defecto | §4.2 |
| **A11Y-01** Botón "Reservar" no operable con teclado | Pendiente: recorrido con Tab, Enter y Espacio. El botón es un `<div onclick>` sin `tabindex` | WCAG 2.1.1 Teclado (A) | Falla nivel A que impide completar el flujo | **P1** | Usar `<button type="button">Reservar</button>` | T4 |
| **SRE-01** SLO incumplido | Presupuesto consumido: D / (T x (1 - SLO)) x 100 = 116.7 %. Pendiente: valores de D, T y SLO | Presupuesto mayor a 100 % (estado rojo) | 116.7 % | **P1** | Congelar funcionalidades nuevas, hacer postmortem y reducir el MTTR con alertas y rollback automático | R5 |
| **UX-01** Fecha en texto libre interpretada mes/día | Se escribe 03/12/2026 y el sistema reserva el 12 de marzo. La confirmación no muestra la fecha. 3 de 5 participantes se enteraron días después | H5 Prevención de errores | 4 (resultado incorrecto silencioso) | **P1** | Usar un selector de fecha y mostrar la fecha completa en la confirmación | R1 |
| **UX-07** Horas mostradas en UTC | La etiqueta dice "franja UTC-0" y Ecuador está en UTC-5. Un participante reservó a las 9:00 creyendo que eran las 14:00 | H2 Correspondencia con el mundo real | 4 (resultado incorrecto silencioso) | **P1** | Mostrar las horas en hora de Ecuador y quitar la jerga "slot de asignación" | T1 |

## 4. Hallazgos P2

| Hallazgo | Evidencia | Criterio violado | Severidad | Prioridad | Recomendación | Ancla |
| --- | --- | --- | --- | --- | --- | --- |
| **SEC-03** Cabeceras de seguridad ausentes | Pendiente: alerta de ZAP con las cabeceras que faltan. Captura `evidencias/zap-cabeceras.png` | A05:2021 Security Misconfiguration (A02:2025), CWE-693 | Media | **P2** | Configurar `Content-Security-Policy`, `X-Content-Type-Options` y `Strict-Transport-Security` | T9 |
| **A11Y-02** Imágenes sin texto alternativo | Unas 40 imágenes, muchas sin `alt`, por ejemplo `top_weather.gif` (página BAD) | WCAG 1.1.1 (A) | Nivel A | **P2** | Agregar `alt` descriptivo, y `alt=""` a las decorativas | T4 |
| **A11Y-03** Enlaces del menú sin nombre | 4 enlaces del menú y 3 enlaces "more" contienen solo una imagen sin `alt` (página BAD) | WCAG 2.4.4 (A) | Nivel A | **P2** | Dar `alt` a la imagen del enlace | T4 |
| **A11Y-04** `<html>` sin atributo `lang` | La etiqueta es `<HTML>` sin `lang` (página BAD) | WCAG 3.1.1 (A) | Nivel A | **P2** | Declarar `<html lang="es">` | T4 |
| **A11Y-05** Mapa sin texto alternativo (S1) | `<img src="mapa-labs.png">` sin `alt` | WCAG 1.1.1 (A) | Nivel A | **P2** | `alt="Mapa con la ubicación de los laboratorios"` | T4 |
| **A11Y-07** Campo de correo sin etiqueta (S4) | `<input type="email" placeholder="Correo institucional">` sin `<label>` | WCAG 3.3.2 (A) | Nivel A | **P2** | Agregar `<label for="correo">Correo institucional</label>` | T4 |
| **A11Y-08** Cierre de sesión sin aviso (S5) | `setTimeout` de 60 s sin aviso ni opción de extender | WCAG 2.2.1 (A) | Nivel A | **P2** | Avisar 20 s antes y permitir extender el tiempo | T4 |
| **A11Y-09** Plantilla sin idioma (S6) | `<html>` sin `lang` en la plantilla base | WCAG 3.1.1 (A) | Nivel A | **P2** | Declarar `<html lang="es">` | T4 |
| **A11Y-10** Error solo con borde rojo (S7) | `.campo-invalido` solo cambia el borde, sin texto | WCAG 3.3.1 (A) | Nivel A | **P2** | Mostrar un texto de error junto al campo | T4 |
| **A11Y-13** Interruptor sin rol ni estado (S10) | `<span class="switch" onclick>` | WCAG 4.1.2 (A) | Nivel A | **P2** | Usar `<button role="switch" aria-checked="true">` | T4 |
| **A11Y-06** Contraste insuficiente (S2) | Texto de 14 px color `#8A8A8A` sobre blanco: 3.45:1 | WCAG 1.4.3 (AA) | Nivel AA | **P2** | Usar un color con contraste de 4.5:1 o más, por ejemplo `#767676` | T5 |
| **A11Y-11** Iconos pequeños en móvil (S8) | `.icono-accion` de 16 x 16 px | WCAG 2.5.8 (AA) | Nivel AA | **P2** | Objetivos de al menos 24 x 24 px | T4 |
| **A11Y-12** Foco de teclado oculto (S9) | `*:focus { outline: none; }` | WCAG 2.4.7 (AA) | Nivel AA | **P2** | Quitar la regla o definir un `:focus-visible` visible | T4 |
| **SRE-02** Criterio de liberación no cumplido | λ(12) = 2.98 defectos por semana, el máximo es 1. Pendiente: parámetros a y b | Regla R6 | Criterio R6 no cumplido | **P2** | Seguir probando y corrigiendo hasta que λ(t) sea 1 o menos, y liberar después de t* | R6 |
| **UX-02** Botón "Reservar" sin respuesta | Tras pulsar, la pantalla no cambia por 6 s. 4 de 5 participantes pulsaron de nuevo y se crearon reservas duplicadas | H1 Visibilidad del estado (secundaria: H5) | 3 | **P2** | Deshabilitar el botón al primer clic y mostrar un indicador de progreso | T3 |
| **UX-03** Error técnico al reservar laboratorio ocupado | Aparece "Error 0x45F: constraint FK_lab_slot violated". Ningún participante supo qué hacer y 2 abandonaron | H9 Ayudar a recuperarse de errores | 3 | **P2** | Mostrar "Ese laboratorio ya está ocupado, elige otro horario" con alternativas | T3 |
| **UX-04** Código de laboratorio que hay que recordar | El código solo aparece en un anexo PDF. 2 de 5 participantes escribieron un código equivocado | H6 Reconocimiento antes que recuerdo | 3 | **P2** | Usar una lista desplegable con nombre y código de cada laboratorio | T1 |
| **UX-05** Asistente sin "Atrás" ni "Cancelar" | En el paso 2 no hay botones. Para corregir el paso 1 los participantes cerraron sesión y empezaron de cero | H3 Control y libertad del usuario | 3 | **P2** | Agregar Atrás y Cancelar en cada paso, conservando los datos | T1 |

## 5. Hallazgos P3

| Hallazgo | Evidencia | Criterio violado | Severidad | Prioridad | Recomendación | Ancla |
| --- | --- | --- | --- | --- | --- | --- |
| **SEC-04** El servidor revela su versión de Apache | Pendiente: cabecera `Server: Apache/...`. Captura `evidencias/zap-banner.png` | A05:2021 Security Misconfiguration (A02:2025), CWE-693 | Baja | **P3** | Ocultar la versión con `ServerTokens Prod` y `ServerSignature Off` | T9 |
| **UX-06** Botón principal inconsistente | Es azul y a la derecha en el paso 1, y gris y a la izquierda en el paso 3. El icono de disquete significa "Enviar" y "Guardar borrador" según la pantalla | H4 Consistencia y estándares | 2 | **P3** | Mismo color y posición en los 3 pasos, un icono distinto por acción y separar "Eliminar" | R1 |
| **UX-08** Pantalla de inicio saturada | 6 avisos y 3 carruseles. "Nueva reserva" queda bajo el pliegue y se encontró en 14 s en promedio | H8 Diseño minimalista | 2 | **P3** | Reducir avisos y carruseles y dejar "Nueva reserva" visible sin hacer scroll | T1 |

## 6. Evidencias

| Archivo | Contenido |
|---|---|
| `evidencias/axe-before.png` | Escaneo de axe DevTools en la página BAD before: 45 problemas (35 críticos y 10 graves) |
| `evidencias/lighthouse-before.png` | Lighthouse Accessibility en la página BAD before: puntaje 56 |
| `evidencias/lighthouse-after.png` | Lighthouse Accessibility en la página BAD after: puntaje 84 |
| `evidencias/zap-*.png` | Alertas de OWASP ZAP |
| `evidencias/postman-idor.png` | Petición IDOR y respuesta, sin tokens visibles |

Las herramientas automáticas no certifican accesibilidad (R3). Los resultados de accesibilidad combinan axe, Lighthouse y revisión manual.

## 7. Nota ética

Las pruebas de seguridad se hicieron solo sobre el entorno de práctica autorizado (R8).
