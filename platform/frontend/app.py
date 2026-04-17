import streamlit as st
import requests

API_URL = "http://localhost:8000/analyze"

st.set_page_config(page_title="Trinetra Platform", layout="centered")
st.title("Trinetra Platform")

uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap"])

if uploaded_file and st.button("Analyze", type="primary"):
    with st.spinner("Analyzing..."):
        try:
            response = requests.post(
                API_URL,
                files={"file": (uploaded_file.name, uploaded_file, "application/octet-stream")},
                timeout=120,
            )
            response.raise_for_status()
            data = response.json()

        except requests.exceptions.ConnectionError:
            st.error("Cannot reach the backend. Make sure the FastAPI server is running.")
            st.stop()

        except requests.exceptions.Timeout:
            st.error("Request timed out.")
            st.stop()

        except requests.exceptions.HTTPError:
            detail = response.json().get("detail", response.text)
            st.error(f"Error: {detail}")
            st.stop()

    st.success("Analysis complete.")

    col1, col2 = st.columns(2)
    col1.metric("Total Packets", data.get("total_packets", "N/A"))
    col2.metric("Dropped Packets", data.get("dropped_packets", "N/A"))

    breakdown = data.get("application_breakdown")
    if breakdown and isinstance(breakdown, dict):
        st.subheader("Application Breakdown")
        st.bar_chart(breakdown)
