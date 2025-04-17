import streamlit as st
import requests
import re
from bs4 import BeautifulSoup
from serpapi import GoogleSearch
import pandas as pd

# 🔑 SerpAPI Key
SERPAPI_KEY = "0a72b64bccab9ced37cbd5c071e9368b829facd6f6e0a7d42d3e89bf8c2f0d55"

# Untrusted domains
IGNORE_SITES = ['intelius.com', 'rocketreach.co', 'zoominfo.com', 'aeroleads.com']

# Generic email usernames that shouldn't be considered executive patterns
GENERIC_EMAILS = ["info", "contact", "admin", "support", "sales", "help"]

def is_valid_source(url):
    return not any(site in url for site in IGNORE_SITES)

def is_executive_email(email):
    local_part = email.split('@')[0].lower()
    return all(not local_part.startswith(gen) for gen in GENERIC_EMAILS)

@st.cache_data(ttl=3600)
def fetch_search_results(query, num=10):
    params = {
        "q": query,
        "num": num,
        "api_key": SERPAPI_KEY,
        "engine": "google",
    }
    try:
        search = GoogleSearch(params)
        results = search.get_dict()
        links = []
        if "organic_results" in results:
            for result in results["organic_results"]:
                links.append({
                    "link": result.get("link", ""),
                    "snippet": result.get("snippet", "")
                })
        return links
    except Exception as e:
        st.error(f"Error fetching results: {e}")
        return []

def extract_domain(email):
    return email.split('@')[-1]

def check_email_exact(email):
    domain = extract_domain(email)
    results = fetch_search_results(f'"{email}"')

    for item in results:
        url = item.get("link", "")
        snippet = item.get("snippet", "")

        if is_valid_source(url) and (email in url or email in snippet):
            if domain in url:
                return f"Verified (Pattern: {email}, Source: {url}, Confidence: 100%)"
            else:
                return f"Verified (Pattern: {email}, Source: {url})"

    return None

def check_domain_pattern(email):
    domain = extract_domain(email)
    domain_query = f'"@{domain}"'
    results = fetch_search_results(domain_query)

    exec_emails_found = []

    for item in results:
        url = item["link"]
        if is_valid_source(url):
            try:
                r = requests.get(url, timeout=10)
                soup = BeautifulSoup(r.text, 'html.parser')
                found_emails = re.findall(r"[a-zA-Z0-9_.+-]+@" + re.escape(domain), soup.text)
                found_emails = list(set(found_emails))
                found_emails = [e for e in found_emails if e.lower() != email.lower()]
                exec_emails = [e for e in found_emails if is_executive_email(e)]
                if exec_emails:
                    return f"Pattern Verified (Based on: {', '.join(exec_emails[:3])}, Source: {url})"
            except:
                continue

    return "Not Verified"

def verify_email(email):
    result = check_email_exact(email)
    if result:
        return result
    else:
        return check_domain_pattern(email)

# Streamlit UI
st.title("📧 Email Verifier Tool")
st.write("Enter email addresses manually or upload a .csv/.txt file.")

email_input = st.text_area("Enter emails separated by comma or newline")
file_upload = st.file_uploader("Or upload a .csv or .txt file", type=["csv", "txt"])

emails = []
if email_input:
    emails += [e.strip() for e in re.split(r'[\n,]+', email_input) if e.strip()]

if file_upload:
    if file_upload.name.endswith(".csv"):
        df_uploaded = pd.read_csv(file_upload, header=None)
        emails += df_uploaded.iloc[:, 0].dropna().astype(str).tolist()
    elif file_upload.name.endswith(".txt"):
        content = file_upload.read().decode("utf-8")
        emails += [e.strip() for e in re.split(r'[\n,]+', content) if e.strip()]

emails = list(set(emails))  # Remove duplicates

if emails:
    if st.button("🔍 Verify Emails"):
        results = []
        for email in emails:
            try:
                status = verify_email(email)
            except Exception as e:
                status = f"Error: {str(e)}"
            results.append({"Email": email, "Status": status})

        df_results = pd.DataFrame(results)
        st.write("## ✅ Verification Results")
        st.dataframe(df_results)

        csv = df_results.to_csv(index=False)
        st.download_button("⬇️ Download Results", csv, "verification_results.csv", "text/csv")
else:
    st.info("Enter at least one email address or upload a file.")
