"""
Run:
    streamlit run dashboard.py --server.port 8501 --server.address 0.0.0.0
Access:
    http://192.168.100.20:8501
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import os, time

ROOT      = os.path.dirname(os.path.dirname(__file__))
PRED_LOG  = os.path.join(ROOT, "data", "predictions.log")
BLOCK_LOG = os.path.join(ROOT, "data", "blocked_ips.log")

COLOURS = {
    "normal" : "#1D9E75",
    "dos"    : "#E24B4A",
    "probe"  : "#7F77DD",
    "r2l"    : "#EF9F27",
    "u2r"    : "#E24B4A",
}

st.set_page_config(
    page_title = "IDS Live Dashboard",
    layout     = "wide",
)

st.title("🛡️ IDS — Live Attack Detection Dashboard")

placeholder = st.empty()

while True:
    try:
        df = pd.read_csv(PRED_LOG)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        attacks = df[df["predicted"] != "normal"]
        total   = len(df)
        n_atk   = len(attacks)
        rate    = round(n_atk / total * 100, 1) if total else 0.0

        with placeholder.container():
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Total Predictions", f"{total:,}")
            c2.metric("Attacks Detected",  f"{n_atk:,}")
            c3.metric("Attack Rate",        f"{rate}%")
            c4.metric("Unique Attacker IPs",
                      attacks["src_ip"].nunique() if n_atk else 0)

            col_a, col_b = st.columns(2)

            with col_a:
                st.subheader("Predictions by Type")
                counts = df["predicted"].value_counts().reset_index()
                counts.columns = ["type", "count"]
                fig = px.bar(counts, x="type", y="count",
                             color="type",
                             color_discrete_map=COLOURS,
                             template="plotly_dark")
                fig.update_layout(showlegend=False,
                                  height=300,
                                  margin=dict(t=10, b=0))
                st.plotly_chart(fig, use_container_width=True)

            with col_b:
                st.subheader("Attack Timeline")
                if n_atk:
                    tl = (attacks
                          .set_index("timestamp")
                          .resample("1min")["predicted"]
                          .count()
                          .reset_index())
                    tl.columns = ["time", "attacks"]
                    fig2 = px.line(tl, x="time", y="attacks",
                                   template="plotly_dark")
                    fig2.update_layout(height=300, margin=dict(t=10))
                    st.plotly_chart(fig2, use_container_width=True)
                else:
                    st.info("No attacks detected yet.")

            st.subheader("Recent Predictions")
            st.dataframe(
                df.tail(20)[["timestamp", "src_ip", "dst_ip",
                             "predicted", "confidence", "true_label"]]
                  .sort_values("timestamp", ascending=False),
                use_container_width=True,
            )

            if os.path.exists(BLOCK_LOG):
                st.subheader("Blocked IPs")
                bl = pd.read_csv(
                    BLOCK_LOG, sep=r"\s+", header=None,
                    names=["ts", "action", "ip", "label", "conf"]
                )
                active = bl[bl["action"] == "BLOCKED"]
                if len(active):
                    st.dataframe(active, use_container_width=True)
                else:
                    st.info("No IPs currently blocked.")

    except FileNotFoundError:
        with placeholder.container():
            st.info("Waiting for predictions.log …")
            st.caption("Make sure predict.py is running on the IDS VM.")

    time.sleep(3)
    st.rerun()
