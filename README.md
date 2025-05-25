# Proyecto-Python
# 🔐 Análisis de Logs de Seguridad con Streamlit

**Autor:** Gabriel  
**Tecnologías:** Python · Pandas · Streamlit · Plotly · Seaborn · Matplotlib  
**Proyecto Final - Curso de Ciencia de Datos**

Este proyecto consiste en una aplicación interactiva desarrollada con **Streamlit**, diseñada para el análisis visual y exploratorio de archivos de logs de red con enfoque en **detección de ciberamenazas**. Utiliza técnicas básicas de ciencia de datos y análisis de texto para identificar y clasificar eventos potencialmente maliciosos en función de la IP y el contenido del mensaje de cada evento.

---

## 🧠 Objetivo

El objetivo del proyecto es:

- Analizar registros de red para **detectar anomalías** y **comportamientos sospechosos**.
- Clasificar eventos por **nivel de gravedad** en función del contenido del mensaje.
- **Identificar IPs maliciosas** comparando con una base de datos externa.
- Facilitar la interpretación de los datos mediante visualizaciones claras e interactivas.

Este enfoque permite a analistas de seguridad obtener una **visión rápida y detallada** del tráfico malicioso presente en un entorno de red.

---

## 🚀 Funcionalidades Destacadas

✅ Carga dinámica de archivos CSV  
✅ Limpieza y preprocesamiento de datos  
✅ Detección de IPs maliciosas por cruce con lista externa  
✅ Clasificación automática de eventos por gravedad  
✅ Visualización de eventos por categoría, hora, protocolo y tipo de ataque  
✅ Filtros interactivos por múltiples dimensiones  
✅ Comparación entre tráfico malicioso y benigno  
✅ Exportación de análisis para informes

---

## 📊 Análisis Realizado

La app analiza registros que contienen, entre otros:

- Fecha y hora del evento
- IP de origen y destino
- Categoría del evento
- Protocolo utilizado
- Mensaje con descripción técnica

A partir de esto se realizan:

### 🔎 Clasificación de Gravedad

Se analizan los mensajes de los logs buscando palabras clave como:

| Palabra clave                         | Gravedad asignada |
|--------------------------------------|-------------------|
| `port scan`, `flood`, `ips detection`| 🚨 Crítico         |
| `dropped`, `unhandled`               | ⚠️ Alto            |
| `assigned ip address`                | 🟡 Medio           |
| Otros                                | 🟢 Bajo            |

---

### 📈 Visualizaciones Incluidas

- **Gráfico de barras**: eventos por categoría
- **Mapa de calor**: actividad por hora y tipo de ataque
- **Gráfico circular**: proporción de eventos críticos
- **Histograma**: cantidad de eventos por hora del día
- **Gráfico de dispersión**: tipos de ataques vs. hora
- **Tablas dinámicas**: IPs más activas y frecuentes

Todas las gráficas son interactivas y se actualizan al aplicar filtros.

---

## 🛠️ Tecnologías Utilizadas

| Tecnología  | Descripción                             |
|-------------|-----------------------------------------|
| **Python**  | Lenguaje principal para análisis        |
| **Pandas**  | Limpieza, transformación y análisis     |
| **Streamlit** | Framework web interactivo para Python |
| **Plotly**  | Visualizaciones interactivas            |
| **Seaborn** | Gráficos estadísticos                   |
| **Matplotlib** | Soporte adicional de visualización   |





