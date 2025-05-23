import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import streamlit as st
import os
import plotly.express as px

st.set_page_config(layout="wide")

log_file = 'C:\\Users\\gabri\\Documents\\Proyecto\\log.csv'
ips_maliciosas_file = 'C:\\Users\\gabri\\Documents\\Proyecto\\logs_con_ips_maliciosas.csv'

# === Cargar los archivos automáticamente al iniciar ===
if os.path.exists(log_file) and os.path.exists(ips_maliciosas_file):
    df = pd.read_csv(log_file)
    df_ips_maliciosas = pd.read_csv(ips_maliciosas_file)

    # === Barra lateral ===
    st.sidebar.header("Opciones")
    st.title("Análisis de Logs de Seguridad")

    # Definir las columnas que se utilizarán
    cols_usadas = [
        "Time", "ID", "Category", "Group", 
        "Src. IP", "Src. Port", "Dst. IP", "Dst. Port", 
        "IP Protocol", "Application", "FW Action", "Message"
    ]
    df = df[cols_usadas].copy()

    # Renombrar las columnas para mayor claridad
    df.rename(columns={
        "Time": "timestamp",
        "ID": "event_code",
        "Category": "category",
        "Group": "subcategory",
        "Src. IP": "src_ip",
        "Src. Port": "src_port",
        "Dst. IP": "dst_ip",
        "Dst. Port": "dst_port",
        "IP Protocol": "protocol",
        "Application": "application",
        "FW Action": "fw_action",
        "Message": "message"
    }, inplace=True)

    # Convertir la columna timestamp a datetime
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    # Rellenar valores faltantes con 'Unknown'
    columnas_a_rellenar = [
        "src_ip", "src_port", "dst_ip", "dst_port", 
        "protocol", "application", "fw_action", "message"
    ]
    columnas_existentes = [col for col in columnas_a_rellenar if col in df.columns]
    df[columnas_existentes] = df[columnas_existentes].fillna("Unknown")

    # Crear la columna hora
    df["hour"] = df["timestamp"].dt.hour

    # === Filtros ===
    st.sidebar.markdown("---")
    categorias = df["category"].dropna().unique()
    protocolos = df["protocol"].dropna().unique()

    categoria_seleccionada = st.sidebar.multiselect("Filtrar por Categoría", sorted(categorias), default=sorted(categorias))
    protocolo_seleccionado = st.sidebar.multiselect("Filtrar por Protocolo", sorted(protocolos), default=sorted(protocolos))
    hora_min, hora_max = int(df["hour"].min()), int(df["hour"].max())
    rango_hora = st.sidebar.slider("Filtrar por Hora", hora_min, hora_max, (hora_min, hora_max))

    # Filtrar el dataframe con los parámetros seleccionados
    df_filtrado = df[
        (df["category"].isin(categoria_seleccionada)) &
        (df["protocol"].isin(protocolo_seleccionado)) &
        (df["hour"] >= rango_hora[0]) & (df["hour"] <= rango_hora[1])
    ]

    # === Visualizaciones ===
    st.subheader("Vista previa del dataset filtrado")
    st.dataframe(df_filtrado.head(600))

    # Eventos por Categoría
    st.subheader("Eventos por Categoría")
    cat_counts = df_filtrado["category"].value_counts().reset_index()
    cat_counts.columns = ["category", "count"]
    fig_cat = px.bar(cat_counts, x="category", y="count", title="Eventos por Categoría", color="category")
    st.plotly_chart(fig_cat, use_container_width=True)

    # Protocolos Usados
    st.subheader("Protocolos Usados")
    proto_counts = df_filtrado["protocol"].value_counts().reset_index()
    proto_counts.columns = ["protocol", "count"]
    fig_proto = px.bar(proto_counts, x="protocol", y="count", title="Protocolos Usados", color="protocol")
    st.plotly_chart(fig_proto, use_container_width=True)

    # Eventos por Hora del Día
    st.subheader("Eventos por Hora del Día")
    hour_counts = df_filtrado["hour"].value_counts().sort_index().reset_index()
    hour_counts.columns = ["hour", "count"]
    fig_hour = px.bar(hour_counts, x="hour", y="count", title="Eventos por Hora del Día", color="hour")
    st.plotly_chart(fig_hour, use_container_width=True)

    # IPs más frecuentes
    st.subheader("IPs más frecuentes")
    st.write("Top 10 IPs de Origen más frecuentes:")
    st.write(df_filtrado["src_ip"].value_counts().head(10))
    st.write("Top 10 IPs de Destino más frecuentes:")
    st.write(df_filtrado["dst_ip"].value_counts().head(10))

    # === Port Scan por hora ===
    port_scan_ataques = df_filtrado[df_filtrado['message'].str.contains('port scan', case=False, na=False)].copy()
    port_scan_ataques['hora'] = port_scan_ataques['timestamp'].dt.hour
    ataques_por_hora_port_scan = port_scan_ataques.groupby(['hora']).size().reset_index(name='ataques')

    plt.figure(figsize=(12, 6))
    ax = sns.lineplot(data=ataques_por_hora_port_scan, x='hora', y='ataques')
    ax.set_title('Número de Ataques de Port Scan por Hora')
    ax.set_xlabel('Hora')
    ax.set_ylabel('Número de Ataques')
    plt.grid(True, axis='y')
    st.pyplot(plt)

    # === Gravedad ===
    def classify_severity(msg):
        msg = str(msg).lower()
        if "port scan" in msg or "flood" in msg or "ips detection" in msg:
            return "Crítico"
        elif "dropped" in msg or "unhandled" in msg:
            return "Alto"
        elif "assigned ip address" in msg:
            return "Medio"
        else:
            return "Bajo"

    df_filtrado['severity'] = df_filtrado['message'].apply(classify_severity)

    plt.figure(figsize=(10, 6))
    ax = sns.countplot(x='severity', data=df_filtrado, hue='severity', palette='viridis', legend=False)
    for container in ax.containers:
        ax.bar_label(container, fontsize=10, padding=5)
    ax.set_title('Distribución de la Gravedad de los Ataques')
    ax.set_xlabel('Gravedad')
    ax.set_ylabel('Número de Ataques')
    plt.grid(True, axis='y')
    st.pyplot(plt)

    # === Eventos por categoría y fecha ===
    df_filtrado['fecha'] = df_filtrado['timestamp'].dt.date
    eventos = df_filtrado.groupby(['fecha', 'category']).size().reset_index(name='eventos')

    plt.figure(figsize=(14, 7))
    ax = sns.countplot(data=df_filtrado, x='fecha', hue='category')
    for container in ax.containers:
        ax.bar_label(container, fontsize=8, padding=2)
    ax.set_title('Conteo de Eventos por Categoría y Fecha')
    ax.set_xlabel('Fecha')
    ax.set_ylabel('Número de Eventos')
    plt.xticks(rotation=45)
    sns.move_legend(ax, "center right", bbox_to_anchor=(1.3, 0.5))
    plt.grid(True, axis='y')
    plt.tight_layout()
    st.pyplot(plt)

    # === Mapa de Calor por Hora ===
    def clasificar_tipo_ataque(msg):
        msg = str(msg).lower()
        if "port scan" in msg:
            return "Port Scan"
        elif "flood" in msg:
            return "Flood"
        elif "ips detection" in msg:
            return "IPS Detection"
        elif "drop" in msg:
            return "Drop"
        else:
            return "Otro"

    df_filtrado['tipo_ataque'] = df_filtrado['message'].apply(clasificar_tipo_ataque)
    heat_data = df_filtrado.groupby(['hour', 'tipo_ataque']).size().unstack(fill_value=0)

    plt.figure(figsize=(12, 6))
    sns.heatmap(heat_data, cmap='magma', annot=True, fmt='d')
    plt.title('Mapa de Calor de Tipos de Ataques por Hora', fontsize=16)
    plt.xlabel('Tipo de Ataque')
    plt.ylabel('Hora del Día')
    plt.tight_layout()
    st.pyplot(plt)

    # === Nueva Gráfica: Mensajes por Hora del Día ===
    eventos = df_filtrado.groupby(['hour', 'message']).size().reset_index(name='cantidad')
    plt.style.use('dark_background')
    plt.figure(figsize=(22, 7))
    ax = sns.lineplot(data=eventos, x='hour', y='cantidad', hue='message', marker='o')
    ax.set_title('Cantidad de Mensajes por Hora del Día', fontsize=18)
    ax.set_xlabel('Hora del Día (12-24)', fontsize=14)
    ax.set_ylabel('Cantidad de Mensajes', fontsize=14)
    sns.move_legend(ax, "center right", bbox_to_anchor=(1.5, 0.5))
    plt.xticks(range(12, 20))
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.tight_layout()
    st.pyplot(plt)

    # === NUEVA GRÁFICA: Dispersión de Ataques por Hora ===
    def clasificar_ataque(mensaje):
        mensaje = str(mensaje).lower()
        if "port scan" in mensaje:
            return "Port Scan"
        elif "icmp time-to-live" in mensaje:
            return "IPS Detection"
        elif "udp flood" in mensaje:
            return "Flood"
        elif "multicast" in mensaje:
            return "Multicast"
        elif "ip address assigned" in mensaje:
            return "DHCP"
        elif "tcp packet dropped" in mensaje:
            return "Drop"
        else:
            return "Otro"

    df_filtrado['tipo_ataque'] = df_filtrado['message'].apply(clasificar_ataque)
    conteo = df_filtrado.groupby(['tipo_ataque', 'hour']).size().reset_index(name='cantidad')
    tipos_frecuentes = conteo.groupby('tipo_ataque')['cantidad'].sum()
    tipos_frecuentes = tipos_frecuentes[tipos_frecuentes > 20].index
    conteo_filtrado = conteo[conteo['tipo_ataque'].isin(tipos_frecuentes)]

    st.subheader("Dispersión de Hora del Día por Tipo de Ataque (según cantidad)")
    plt.figure(figsize=(14, 6))
    out1 = sns.scatterplot(
        data=conteo_filtrado,
        x='tipo_ataque',
        y='hour',
        size='cantidad',
        hue='cantidad',
        palette='Blues',
        sizes=(50, 300),
        legend='brief'
    )
    out1.set_title("Dispersión de Hora del Día por Tipo de Ataque (según cantidad)", fontsize=16)
    out1.set_xlabel("Tipo de Ataque")
    out1.set_ylabel("Hora del Día")
    plt.xticks(rotation=45)
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.tight_layout()
    st.pyplot(plt)

    # === Análisis de Protocolo vs Gravedad ===
    st.subheader("Relación entre Protocolo y Gravedad del Evento")
    st.markdown("Cruzamos el protocolo con la gravedad del evento para analizar si ciertos protocolos son más propensos a generar eventos graves.")
    plt.style.use('default')
    plt.figure(figsize=(12, 6))
    ax = sns.countplot(data=df_filtrado, x='protocol', hue='severity')
    ax.set_title("Eventos por Protocolo y Nivel de Gravedad")
    ax.set_xlabel("Protocolo")
    ax.set_ylabel("Número de Eventos")
    plt.xticks(rotation=45)
    plt.grid(True, axis='y')
    plt.tight_layout()
    st.pyplot(plt)

    # === TOP 4 IP DE DESTINO ===
    ataques_criticos = df_filtrado[df_filtrado['severity'] == 'Crítico']
    top_ips_origen = ataques_criticos["src_ip"].value_counts().head(10)


    import plotly.express as px

    st.subheader("TOP 10 IP de Origen en Ataques Críticos")

    top_ips_df = top_ips_origen.reset_index()
    top_ips_df.columns = ['src_ip', 'num_ataques']

    fig = px.bar(
        top_ips_df,
        x='src_ip',
        y='num_ataques',
        color='num_ataques',
        color_continuous_scale='Reds',
        title="Top 10 IP de Origen en Ataques Críticos",
        labels={"src_ip": "IP de Origen", "num_ataques": "Número de Ataques Críticos"},
        text='num_ataques'
   )

    fig.update_layout(
       xaxis_title="IP de Origen",
       yaxis_title="Número de Ataques Críticos",
       title_x=0.5
   )


    df_maliciosas = pd.read_csv("logs_con_ips_maliciosas.csv")
    df["src_ip"] = df["src_ip"].astype(str)
    df_maliciosas["IP"] = df_maliciosas["IP"].astype(str)

    # Añadir columna indicando si la IP es maliciosa: 0 = maliciosa, 1 = no maliciosa
    df["es_maliciosa"] = df["src_ip"].apply(lambda ip: 0 if ip in df_maliciosas["IP"].values else 1)

    st.plotly_chart(fig, use_container_width=True)
    st.subheader("Vista de Logs con IPs Maliciosas y No Maliciosas")
    st.dataframe(df[['timestamp', 'src_ip', 'dst_ip', 'category', 'event_code', 'es_maliciosa']])

     # Gráfico por hora diferenciando IPs maliciosas
    st.subheader("Distribución Horaria de Eventos (IPs Maliciosas vs No Maliciosas)")
    plt.figure(figsize=(12, 6))
    sns.countplot(data=df, x="hour", hue="es_maliciosa", palette="Set2")
    plt.title("Eventos por hora según si la IP es maliciosa o no lo es")
    plt.xlabel("Hora")
    plt.ylabel("Número de eventos")
    plt.legend(title="¿IP maliciosa?", labels=["Sí (0)", "No (1)"])
    st.pyplot(plt)


    