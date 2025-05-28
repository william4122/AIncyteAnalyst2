import streamlit as st
import json
import pandas as pd
from collections import Counter
import ollama

st.set_page_config(page_title="AIncyte Analyst", layout="wide")
st.title("Incyte Analyst")

uploaded_file = st.file_uploader("Upload NDJSON Telemetry", type=["ndjson"])

if uploaded_file:
    raw_lines = uploaded_file.read().decode("utf-8").strip().split("\n")
    data = [json.loads(line) for line in raw_lines]
    df = pd.json_normalize(data)

    st.success(f"Loaded {len(df)} telemetry events.")
    st.dataframe(df.head(10), use_container_width=True)

    query = st.text_input("Ask a question about this telemetry:")

    def apply_filters(query_text):
        filters = []

        if "high threat" in query_text.lower():
            filters.append(lambda row: row.get("ip_reputation", {}).get("threat_score", 0) >= 0.9)

        if "udp" in query_text.lower():
            filters.append(lambda row: row.get("proto", "").lower() == "udp")
        elif "tcp" in query_text.lower():
            filters.append(lambda row: row.get("proto", "").lower() == "tcp")

        return filters

    def filter_df(query_text, df):
        filters = apply_filters(query_text)
        for f in filters:
            df = df[df.apply(f, axis=1)]
        return df

    def summarize_rows(filtered_df, max_rows=10):
        summaries = []
        for _, row in filtered_df.head(max_rows).iterrows():
            rep = row.get("ip_reputation", {})
            summaries.append(
                f"{row['proto']} connection from {row['localAddr']} to {row['remoteAddr']}:{row['remotePort']} (score: {rep.get('threat_score', 0)}, tags: {rep.get('tags', '-')})"
            )
        return summaries

    def handle_statistical_questions(query_text, df):
        output = []

        if "common remote address" in query_text.lower():
            top = Counter(df["remoteAddr"]).most_common(5)
            output.append("Top remoteAddr:")
            output += [f"- {ip} ({count} times)" for ip, count in top]

        if "common local address" in query_text.lower():
            top = Counter(df["localAddr"]).most_common(5)
            output.append("Top localAddr:")
            output += [f"- {ip} ({count} times)" for ip, count in top]

        if "is" in query_text.lower() and "unusual" in query_text.lower():
            for ip in df["remoteAddr"].unique():
                count = (df["remoteAddr"] == ip).sum()
                if count <= 2:
                    output.append(f"{ip} is rare: seen {count} times")
        return output

    if query:
        with st.spinner("Analyzing telemetry and querying Incyte Analyst..."):
            stat_output = handle_statistical_questions(query, df)
            filtered_df = filter_df(query, df)
            summaries = summarize_rows(filtered_df)

            context = "\n".join(stat_output + summaries)

            prompt = f"""
You are a senior cybersecurity analyst mentoring a junior. Here is relevant telemetry context:

{context}

User question: {query}

Provide a thoughtful, step-by-step analysis with investigation recommendations.
"""

            response = ollama.chat(model="llama3", messages=[{"role": "user", "content": prompt}])
            st.markdown("### Analysis")
            st.write(response['message']['content'])
