# Informe de auditoría de liberación — ReservaLab

**Curso:** Aseguramiento de la Calidad de Software · Unidad 3 · Clase 16
**Alcance:** flujo de reserva de laboratorio (usabilidad, accesibilidad WCAG 2.2 AA, confiabilidad, seguridad web)
**Fuente de criterios:** *Clase 16 – Fundamentos teóricos* (noviembre 2026). Las anclas (§, T, F, R) remiten a ese documento.

> Las capturas están en [`evidencias/`](evidencias/). Este informe no contiene contraseñas, tokens ni datos personales.

---

## 1. Veredicto

# ❌ NO-GO

**Justificación:** No-Go porque hay seis hallazgos P1 abiertos: **SEC-01** (SQLi crítica), **SEC-02** (IDOR), **A11Y-01** (botón Reservar no operable con teclado, 2.1.1 nivel A), **SRE-01** (presupuesto de error al 116.7 %, SLO incumplido), **UX-01** (fecha interpretada mes/día, severidad 4) y **UX-07** (horas en UTC que producen una reserva en horario equivocado, severidad 4). R9 exige No-Go con un solo P1 abierto. `R9 · T11`

## 2. Resumen de hallazgos

| ID | Título | Dominio | Severidad de origen | Prioridad |
|---|---|---|---|---|
| SEC-01 | Inyección SQL en endpoint público | Seguridad | Crítica | **P1** |
| SEC-02 | IDOR en `/api/facturas/{id}` | Seguridad | Alta | **P1** |
| A11Y-01 | Botón "Reservar" no operable con teclado | Accesibilidad | 2.1.1 (A) | **P1** |
| SRE-01 | SLO incumplido: 116.7 % del presupuesto | Confiabilidad | > 100 % | **P1** |
| UX-01 | Fecha en texto libre interpretada mes/día | Usabilidad | 4 | **P1** |
| UX-02 | Botón "Reservar" sin retroalimentación (doble clic) | Usabilidad | 3 | P2 |
| UX-03 | Error técnico al reservar laboratorio ocupado | Usabilidad | 3 | P2 |
| A11Y-02 | Imágenes sin texto alternativo | Accesibilidad | 1.1.1 (A) | P2 |
| A11Y-03 | Enlaces del menú sin nombre accesible | Accesibilidad | 2.4.4 (A) | P2 |
| A11Y-04 | `<html>` sin atributo `lang` | Accesibilidad | 3.1.1 (A) | P2 |
| UX-04 | Código de laboratorio debe recordarse y escribirse | Usabilidad | 3 | P2 |
| UX-05 | Asistente sin "Atrás" ni "Cancelar" | Usabilidad | 3 | P2 |
| UX-06 | Botón principal inconsistente entre pasos | Usabilidad | 2 | P3 |
| UX-07 | Horas mostradas en UTC (reserva en horario equivocado) | Usabilidad | 4 | **P1** |
| UX-08 | Pantalla saturada; "Nueva reserva" bajo el pliegue | Usabilidad | 2 | P3 |
| SRE-02 | Criterio de liberación R6 no cumplido: λ(12) = 2.98 defectos/semana | Confiabilidad | R6 (> 1 por semana) | P2 |
| SEC-03 | Cabeceras de seguridad ausentes | Seguridad | Media | P2 |
| A11Y-05 | Mapa de laboratorios sin texto alternativo (S1) | Accesibilidad | 1.1.1 (A) | P2 |
| A11Y-06 | Texto de ayuda con contraste 3.45:1 (S2) | Accesibilidad | 1.4.3 (AA) | P2 |
| A11Y-07 | Campo de correo sin etiqueta visible (S4) | Accesibilidad | 3.3.2 (A) | P2 |
| A11Y-08 | Cierre de sesión a los 60 s sin aviso ni extensión (S5) | Accesibilidad | 2.2.1 (A) | P2 |
| A11Y-09 | Plantilla base sin idioma declarado (S6) | Accesibilidad | 3.1.1 (A) | P2 |
| A11Y-10 | Error de fecha indicado solo con borde rojo (S7) | Accesibilidad | 3.3.1 (A) | P2 |
| A11Y-11 | Iconos de acción de 16 px en móvil (S8) | Accesibilidad | 2.5.8 (AA) | P2 |
| A11Y-12 | Foco de teclado oculto con `outline: none` (S9) | Accesibilidad | 2.4.7 (AA) | P2 |
| A11Y-13 | Interruptor "Recibir recordatorio" sin rol ni estado (S10) | Accesibilidad | 4.1.2 (A) | P2 |
| SEC-04 | El servidor revela su versión de Apache | Seguridad | Baja | P3 |

> Desempate dentro de una misma prioridad: seguridad → accesibilidad nivel A → confiabilidad → usabilidad. `T11`
> Las severidades de UX-01 a UX-08 provienen de la clasificación de la estación de usabilidad (R1). Conteo: P1 = 6, P2 = 18, P3 = 3 (A11Y-02 a A11Y-04 son de la página de práctica W3C BAD).

---

## 3. Hallazgos P1 (bloqueantes)

### SEC-01 — Inyección SQL en endpoint público
| Campo | Contenido |
|---|---|
| **Evidencia** | TODO: petición (endpoint, parámetro, payload), respuesta observada y alerta de ZAP. Captura: `evidencias/zap-sqli.png` |
| **Criterio violado** | A03:2021 Injection (A05:2025) · CWE-89 |
| **Severidad de origen** | Crítica (CVSS 9.0–10.0) |
| **Prioridad** | P1 |
| **Recomendación** | Reemplazar la concatenación por consultas parametrizadas / ORM; validar por lista permitida; usar cuenta de BD con privilegio mínimo; no mostrar errores internos. |
| **Ancla** | §4.4 · T9 · T10 · T11 |

### SEC-02 — IDOR en `/api/facturas/{id}`
| Campo | Contenido |
|---|---|
| **Evidencia** | `GET /api/facturas/552` con el token de la usuaria A devuelve **200** con datos del usuario B (se esperaba 403/404). Captura: `evidencias/postman-idor.png` |
| **Criterio violado** | A01:2021 Broken Access Control (A01:2025) · API1 BOLA · CWE-639 |
| **Severidad de origen** | Alta (CVSS 7.0–8.9) |
| **Prioridad** | P1 |
| **Recomendación** | Verificar propiedad del recurso en el servidor (`WHERE id = ? AND owner_id = usuario_actual`); denegar por defecto; registrar y alertar fallos de autorización. Test automatizado en Postman: respuesta `oneOf([403, 404])`. |
| **Ancla** | §4.2 · T9 · T10 · T11 |

### A11Y-01 — Botón "Reservar" no operable con teclado
| Campo | Contenido |
|---|---|
| **Evidencia** | TODO: recorrido con Tab/Enter/Espacio; elemento afectado (¿`<div onclick>` sin `tabindex`?); regla de axe si aplica. Captura: `evidencias/axe-teclado.png` |
| **Criterio violado** | WCAG 2.1.1 Teclado (nivel A, principio Operable) |
| **Severidad de origen** | Falla nivel A que impide completar un flujo crítico |
| **Prioridad** | P1 |
| **Recomendación** | Usar `<button>` nativo, o añadir `tabindex="0"`, `role="button"` y manejadores de Enter/Espacio. Verificar de nuevo solo con teclado. |
| **Ancla** | §2.4 · T4 · R2 · R3 · T11 |

### SRE-01 — SLO incumplido (presupuesto de error al 116.7 %)
| Campo | Contenido |
|---|---|
| **Evidencia** | TODO: SLO, ventana, D (indisponibilidad total) y T. Cálculo: `D / (T · (1 − SLO)) × 100 = 116.7 %`. |
| **Criterio violado** | Presupuesto consumido > 100 % → estado Rojo (SLO incumplido) |
| **Severidad de origen** | 116.7 % del presupuesto |
| **Prioridad** | P1 |
| **Recomendación** | Congelar nuevas funcionalidades; solo correcciones de confiabilidad y seguridad hasta recuperar el presupuesto; postmortem obligatorio; reducir MTTR con monitoreo, alertas, runbooks y rollback automatizado. |
| **Ancla** | §3.3 · T6 · R5 · T11 |

### UX-01 — Fecha en texto libre interpretada mes/día
| Campo | Contenido |
|---|---|
| **Evidencia** | TODO: pantalla, fecha ingresada y fecha reservada. Captura: `evidencias/ux-fecha.png`. El usuario reserva el día equivocado sin darse cuenta. |
| **Criterio violado** | H5 Prevención de errores (principal) |
| **Severidad de origen** | 4 — resultado incorrecto silencioso (R1) |
| **Prioridad** | P1 |
| **Recomendación** | Reemplazar el texto libre por un selector de fecha y mostrar la fecha completa en la confirmación. |
| **Ancla** | §1.2 · T1 · T2 · R1 · T3 · T11 |

### UX-07 — Horas mostradas en UTC
| Campo | Contenido |
|---|---|
| **Evidencia** | La etiqueta dice "Slot de asignación (franja UTC-0)" y las horas se muestran en UTC; Ecuador está en UTC-5. Un participante reservó a las 9:00 creyendo que eran las 14:00. TODO: captura `evidencias/ux-utc.png` |
| **Criterio violado** | H2 Correspondencia entre el sistema y el mundo real (jerga y unidades ajenas al usuario) |
| **Severidad de origen** | 4 — resultado incorrecto silencioso (R1), en el flujo principal de reserva |
| **Prioridad** | P1 |
| **Recomendación** | Mostrar y recibir las horas en hora de Ecuador (UTC-5) y reemplazar la jerga "slot de asignación / franja UTC-0" por "Horario". |
| **Ancla** | T1 · R1 · T11 |

---

## 4. Hallazgos P2 y P3

### Usabilidad

**UX-02 — Botón "Reservar" sin retroalimentación.** Evidencia: TODO. Criterio: H1 Visibilidad del estado (principal), H5 (secundaria). Severidad 3 → P2. Recomendación: deshabilitar el botón al primer clic y mostrar un indicador de progreso. Ancla: §1.4 · T3 (H1 vs H5) · R1 · T11.

**UX-03 — Error técnico al reservar un laboratorio ocupado.** Evidencia: TODO. Criterio: H9. Severidad 3 (propuesta) → P2. Recomendación: reemplazar el error técnico por un mensaje claro: "Ese laboratorio ya está ocupado, elige otro horario", con alternativas disponibles. Ancla: T1 · T3 (H5 vs H9) · R1 · T11.

**UX-04 — Código de laboratorio que se debe recordar y escribir.** Evidencia: TODO. Criterio: H6 Reconocimiento antes que recuerdo. Severidad 3 (2 de 5 participantes escribieron un código equivocado) → P2. Recomendación: reemplazar el campo de código por una lista desplegable con nombre y código de cada laboratorio. Ancla: T1 · T3 (H6 vs H10) · R1 · T11.

**UX-05 — Asistente sin "Atrás" ni "Cancelar".** Evidencia: TODO. Criterio: H3 Control y libertad del usuario. Severidad 3 (propuesta) → P2. Recomendación: agregar botones Atrás y Cancelar en cada paso conservando los datos ya ingresados. Ancla: T1 · T3 (H3 vs H7) · R1 · T11.

**UX-06 — Botón principal inconsistente.** Evidencia: TODO. Criterio: H4 Consistencia y estándares. Severidad 2 (propuesta) → P3. Recomendación: unificar el botón principal (mismo color y posición) en los 3 pasos, usar un icono distinto para cada acción y diferenciar o separar "Eliminar". Ancla: T1 · §1.4 · T11.

**UX-08 — Pantalla saturada.** Evidencia: TODO. Criterio: H8 Diseño estético y minimalista. Severidad 2 (propuesta) → P3. Recomendación: reducir los avisos y carruseles y dejar "Nueva reserva" visible sin hacer scroll. Ancla: T1 · §1.4 · T11.

### Accesibilidad (WCAG 2.2 AA)

Al fallar criterios de nivel A, el proceso de reserva no alcanza ningún nivel de conformidad (R2). A11Y-02 a A11Y-04 provienen del escaneo de la página de práctica W3C BAD (before); A11Y-05 a A11Y-13 provienen de la revisión del código de ReservaLab (fragmentos S1 a S10). Capturas: `evidencias/axe-*.png`, `evidencias/lighthouse.png`.

**A11Y-02 — Imágenes sin texto alternativo.** Evidencia: hay unas 40 imágenes y muchas no tienen `alt`, por ejemplo `top_weather.gif` y las imágenes del menú. Criterio: WCAG 1.1.1 Contenido no textual (A). Prioridad P2 (otra falla de nivel A). Recomendación: añadir `alt` descriptivo a las imágenes informativas y `alt=""` a las decorativas. Ancla: T4 · T11.

**A11Y-03 — Enlaces del menú sin nombre accesible.** Evidencia: los 4 enlaces del menú principal (Home, News, Tickets, Survey) y 3 enlaces "more" aparecen sin nombre porque contienen solo una imagen sin `alt`. Criterio: WCAG 2.4.4 Propósito de los enlaces (A); relacionado con 4.1.2 y 1.1.1. Prioridad P2. Recomendación: dar `alt` a la imagen del enlace o texto/`aria-label` al enlace. Ancla: T4 · T11.

**A11Y-04 — `<html>` sin atributo `lang`.** Evidencia: la etiqueta es `<HTML>` sin `lang`. Criterio: WCAG 3.1.1 Idioma de la página (A). Prioridad P2. Recomendación: declarar `<html lang="es">`. Ancla: T4 · T11.

**A11Y-05 — Mapa sin texto alternativo (S1).** Evidencia: `<img src="mapa-labs.png">` sin `alt`. Criterio: WCAG 1.1.1 (A, Perceptible). Prioridad P2 (otra falla de nivel A). Recomendación: `alt="Mapa con la ubicación de los laboratorios"`. Ancla: T4 · T11.

**A11Y-06 — Contraste insuficiente en el texto de ayuda (S2).** Evidencia: texto de 14 px, peso normal, color `#8A8A8A` sobre blanco, contraste medido 3.45:1 (mínimo 4.5:1). Criterio: WCAG 1.4.3 (AA, Perceptible). Prioridad P2. Recomendación: usar un color con contraste ≥ 4.5:1, por ejemplo `#767676` o más oscuro (con 24 px, o 18.66 px en negrita, bastaría 3:1). Ancla: T5 · T11.

**A11Y-07 — Campo de correo sin etiqueta (S4).** Evidencia: `<input type="email" placeholder="Correo institucional">` sin `<label>`; el placeholder desaparece al escribir. Criterio: WCAG 3.3.2 (A, Comprensible). Prioridad P2. Recomendación: `<label for="correo">Correo institucional</label>`. Ancla: T4 · T11.

**A11Y-08 — Cierre de sesión sin aviso (S5).** Evidencia: `setTimeout(... cerrarSesion() ..., 60000)` sin aviso ni opción de extender. Criterio: WCAG 2.2.1 (A, Operable). Prioridad P2. Recomendación: avisar al menos 20 s antes y permitir extender o desactivar el límite. Ancla: T4 · T11.

**A11Y-09 — Plantilla sin idioma declarado (S6).** Evidencia: `<!doctype html><html>` sin `lang` en la plantilla base. Criterio: WCAG 3.1.1 (A, Comprensible). Prioridad P2. Recomendación: `<html lang="es">`. Ancla: T4 · T11.

**A11Y-10 — Error de fecha solo con borde rojo (S7).** Evidencia: `.campo-invalido { border: 2px solid #d32f2f; }` sin ningún texto de error. Criterio: WCAG 3.3.1 (A, Comprensible). Prioridad P2. Recomendación: mostrar un texto de error junto al campo y asociarlo con `aria-describedby`. Ancla: T4 · T11.

**A11Y-11 — Objetivos táctiles pequeños (S8).** Evidencia: `.icono-accion { width:16px; height:16px; margin:2px; }` en la versión móvil (editar, duplicar, eliminar). Criterio: WCAG 2.5.8 (AA, Operable). Prioridad P2. Recomendación: objetivos de al menos 24×24 px CSS (idealmente 44). Ancla: T4 · T11.

**A11Y-12 — Foco de teclado oculto (S9).** Evidencia: `*:focus { outline: none; }` sin reemplazo. Criterio: WCAG 2.4.7 (AA, Operable). Prioridad P2. Recomendación: quitar la regla o definir un `:focus-visible` con contorno visible. Ancla: T4 · T11.

**A11Y-13 — Interruptor sin rol ni estado (S10).** Evidencia: `<span class="switch on" onclick="toggle(this)">`. Criterio: WCAG 4.1.2 (A, Robusto). Prioridad P2. Recomendación: `<button role="switch" aria-checked="true">Recibir recordatorio</button>`. Ancla: T4 · T11.

> **R3:** estos resultados provienen de axe/Lighthouse más revisión manual. Una herramienta automática no certifica conformidad.

### Confiabilidad

**SRE-02 — Criterio de liberación por crecimiento de confiabilidad no cumplido.** Evidencia: la intensidad estimada λ(12) = 2.98 defectos por semana de prueba supera el objetivo de 1 por semana. TODO: parámetros a y b (Goel-Okumoto) y t* = ln(a·b / 1) / b. Criterio: R6. Severidad de origen: criterio de liberación R6 no cumplido. Prioridad P2. Recomendación: continuar probando y corrigiendo hasta que λ(t) ≤ 1 defecto/semana; la fecha de liberación debe ser posterior a t*. Ancla: F9 · R6 · T11.

### Seguridad

**SEC-03 — Cabeceras de seguridad ausentes.** Evidencia: TODO: alerta pasiva de ZAP (evidencia E5), con las cabeceras que faltan (`Content-Security-Policy`, `X-Content-Type-Options`, `Strict-Transport-Security`). Captura: `evidencias/zap-cabeceras.png`. Criterio: A05:2021 Security Misconfiguration (A02:2025) · CWE-693. Severidad de origen: Media (CVSS 4.0–6.9). Prioridad P2. Recomendación: configurar las cabeceras en el servidor o proxy y volver a escanear. Ancla: T9 · T10 · T11.

**SEC-04 — El servidor revela su versión de Apache.** Evidencia: TODO: cabecera `Server: Apache/…` en la respuesta HTTP. Captura: `evidencias/zap-banner.png`. Criterio: A05:2021 Security Misconfiguration (A02:2025) · CWE-693 / CWE-209. Severidad de origen: Baja (CVSS 0.1–3.9). Prioridad P3. Recomendación: ocultar la versión (`ServerTokens Prod` y `ServerSignature Off`). Ancla: T9 · T10 · T11.

---

## 5. Evidencias

| Archivo | Contenido |
|---|---|
| `evidencias/axe-*.png` | Escaneo de axe DevTools |
| `evidencias/lighthouse.png` | Informe de Lighthouse (Accessibility) |
| `evidencias/zap-*.png` | Alertas de OWASP ZAP |
| `evidencias/postman-idor.png` | Petición IDOR y respuesta (sin tokens visibles) |

## 6. Nota ética

Las pruebas de seguridad se ejecutaron solo sobre el entorno de práctica autorizado. `R8`
