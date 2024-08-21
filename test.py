import ssl
import socket
import requests
from datetime import datetime
import streamlit as st
import pandas as pd
import os
import base64
import altair as alt  # Ensure you import Altair
import concurrent.futures

def get_certificate_details(hostname):
    try:
        hostname = hostname.strip()  # Remove any leading or trailing whitespace
        # Using the requests library to make an HTTP request
        response = requests.get(f'https://{hostname}', timeout=10, verify=True)
        cert = response.raw.connection.sock.getpeercert()
        expiry_date_str = cert['notAfter']
        expiry_date = datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y %Z')
        issuer = dict(x[0] for x in cert['issuer'])
        issuer_name = issuer.get('organizationName', 'Unknown Issuer')
        return expiry_date, issuer_name
    except requests.exceptions.RequestException as e:
        raise Exception(f"Request error: {str(e)} for hostname {hostname}")
    except ssl.SSLError as ssl_error:
        raise Exception(f"SSL error: {ssl_error} for hostname {hostname}")
    except socket.error as socket_error:
        raise Exception(f"Socket error: {socket_error} for hostname {hostname}")
    except Exception as general_error:
        raise Exception(f"General error: {general_error} for hostname {hostname}")

def check_certificate_expiry(hostnames):
    results = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_hostname = {executor.submit(get_certificate_details, hostname): hostname for hostname in hostnames}
        for future in concurrent.futures.as_completed(future_to_hostname):
            hostname = future_to_hostname[future]
            try:
                expiry_date, issuer_name = future.result()
                current_date = datetime.now()
                days_until_expiry = (expiry_date - current_date).days
                percentage_expired = max(0, 100 - days_until_expiry * 100 / 365)

                if days_until_expiry < 30:
                    status = "⚠️ Expiring Soon"
                else:
                    status = "✅ Valid"

                results.append({
                    "Hostname": hostname,
                    "Expiry Date": expiry_date.strftime('%Y-%m-%d'),
                    "Issuer": issuer_name,
                    "Days Until Expiry": days_until_expiry,
                    "Status": status,
                    "Progress": percentage_expired,
                })
            except Exception as e:
                results.append({
                    "Hostname": hostname,
                    "Expiry Date": "N/A",
                    "Issuer": "N/A",
                    "Days Until Expiry": "N/A",
                    "Status": f"❌ Error: {str(e)}",
                    "Progress": 0,
                })
    return results

def load_urls_from_file(filename):
    try:
        with open(filename, 'r') as file:
            urls = [line.strip() for line in file]  # Strip each line of whitespace
        return urls
    except Exception as e:
        st.error(f"Error loading {filename}: {str(e)}")
        return []

# Streamlit application
def main():
    st.set_page_config(page_title="SSL Checker", page_icon="🔒")
    st.title("🔒 SSL Certificate Expiry Checker")
    st.markdown("Check if your website's SSL certificate is about to expire. Stay secure by renewing certificates on time!")

    # Display an image aligned to the left and scaled down
    image_path = "/mnt/e/OneDrive_1_4-27-2022/Cert/Full-Automation-cert-flip/ssl-main/images2.png"
    if os.path.exists(image_path):
        with open(image_path, "rb") as image_file:
            image_data = image_file.read()
            encoded_image = base64.b64encode(image_data).decode()
        st.markdown(
            f"""
            <div style="text-align: left;">
                <img src="data:image/png;base64,{encoded_image}" alt="SSL Checker" style="width: 200px; height: 50px;">
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        st.error("Image file not found. Please check the file path.")

    with st.expander("ℹ️ Instructions"):
        st.write("Press the button for the desired pod to check the SSL certificate expiry dates of the URLs in the corresponding text file.")

    # Buttons for each pod
    if st.button("Check US1"):
        hostnames = load_urls_from_file("uspod1.txt")
        results = check_certificate_expiry(hostnames)
        display_results(results)

    if st.button("Check US2"):
        hostnames = load_urls_from_file("uspod2.txt")
        results = check_certificate_expiry(hostnames)
        display_results(results)

    if st.button("Check US3"):
        hostnames = load_urls_from_file("uspod3.txt")
        results = check_certificate_expiry(hostnames)
        display_results(results)

    if st.button("Check US4"):
        hostnames = load_urls_from_file("uspod4.txt")
        results = check_certificate_expiry(hostnames)
        display_results(results)

    if st.button("Check IN03"):
        hostnames = load_urls_from_file("In03.txt")
        results = check_certificate_expiry(hostnames)
        display_results(results)

    if st.button("Check EU01"):
        hostnames = load_urls_from_file("Eu1.txt")
        results = check_certificate_expiry(hostnames)
        display_results(results)     

    if st.button("Check EU02"):
        hostnames = load_urls_from_file("Eu2.txt")
        results = check_certificate_expiry(hostnames)
        display_results(results)

    if st.button("Check AU01"):
        hostnames = load_urls_from_file("au01.txt")
        results = check_certificate_expiry(hostnames)
        display_results(results)

    if st.button("Check AE01"):
        hostnames = load_urls_from_file("ae01.txt")
        results = check_certificate_expiry(hostnames)
        display_results(results)

    if st.button("Check CA01"):
        hostnames = load_urls_from_file("ca01.txt")
        results = check_certificate_expiry(hostnames)
        display_results(results)

    if st.button("Check UK01"):
        hostnames = load_urls_from_file("uk01.txt")
        results = check_certificate_expiry(hostnames)
        display_results(results)        

    if st.button("Check MXP01"):
        hostnames = load_urls_from_file("mxp01.txt")
        results = check_certificate_expiry(hostnames)
        display_results(results)  

    if st.button("Check KSA01"):
        hostnames = load_urls_from_file("ksa01.txt")
        results = check_certificate_expiry(hostnames)
        display_results(results)         

    if st.button("Check FED-HIGH01"):
        hostnames = load_urls_from_file("fedhigh01.txt")
        results = check_certificate_expiry(hostnames)
        display_results(results)  

    if st.button("Check SITE01"):
        hostnames = load_urls_from_file("site01.txt")
        results = check_certificate_expiry(hostnames)
        display_results(results) 

    if st.button("Check MPOD01"):
        hostnames = load_urls_from_file("mpod01.txt")
        results = check_certificate_expiry(hostnames)
        display_results(results)  

def display_results(results):
    st.subheader("Results")

    # Convert results to DataFrame
    df = pd.DataFrame(results)

    # Display as DataFrame with progress bars
    st.dataframe(df.style.applymap(
        lambda val: "color: red;" if val == "⚠️ Expiring Soon" else "color: green;",
        subset=["Status"]
    ).bar(subset=["Progress"], color=["#d65f5f", "#5fba7d"], vmin=0, vmax=100))

    # Filter out rows with non-numeric Days Until Expiry
    df_filtered = df[df['Days Until Expiry'] != 'N/A']
    df_filtered['Days Until Expiry'] = df_filtered['Days Until Expiry'].astype(int)
    
    # Bar chart showing Days Until Expiry for each Hostname
    if not df_filtered.empty:
        st.subheader("Days Until Expiry for Each Hostname")
        
        # Use altair for the bar chart with conditional colors
        bar_chart = alt.Chart(df_filtered).mark_bar().encode(
            x=alt.X('Hostname:N', sort='-y'),
            y='Days Until Expiry:Q',
            color=alt.Color('Days Until Expiry:Q', scale=alt.Scale(domain=[0, 30, 365], range=['red', 'orange', 'green'])),
            tooltip=['Hostname', 'Days Until Expiry', 'Expiry Date', 'Issuer', 'Status']
        ).properties(
            width=600,
            height=400
        )
        
        st.altair_chart(bar_chart, use_container_width=True)

if __name__ == "__main__":
    main()
