import streamlit as st
import sqlite3
import pandas as pd

st.title("DeepWAF-XAI Security Dashboard")

import os
from pathlib import Path
_base_dir = Path(__file__).resolve().parent.parent
_db_path = os.getenv("DEEPWAF_LOGS_DB_PATH", str(_base_dir / "database" / "logs.db"))
conn = sqlite3.connect(_db_path)

df = pd.read_sql_query("SELECT * FROM attack_logs", conn)

st.subheader("Total Attacks Detected")

st.metric("Total Attacks", len(df))

st.subheader("Recent Attack Logs")

st.dataframe(df.tail(10))

st.subheader("Attack Distribution")

attack_counts = df['attack_type'].value_counts()

st.bar_chart(attack_counts)