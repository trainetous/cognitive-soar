# app.py
import streamlit as st
import pandas as pd
from pycaret.classification import load_model as load_classification_model, predict_model as predict_classification
from pycaret.clustering import load_model as load_clustering_model, predict_model as predict_clustering
from genai_prescriptions import generate_prescription
import os
import time

# --- Page Configuration ---
st.set_page_config(
    page_title="Cognitive SOAR: Phishing Attribution System",
    page_icon="🛡️",
    layout="wide"
)

# --- Threat Actor Profiles ---
THREAT_ACTOR_PROFILES = {
    0: {
        "name": "State-Sponsored APT",
        "description": "Advanced Persistent Threat actors backed by nation-states",
        "characteristics": [
            "Highly sophisticated and well-resourced",
            "Uses valid SSL certificates to appear legitimate",
            "Employs subtle deception techniques like prefix/suffix manipulation",
            "Targets high-value government and corporate entities",
            "Maintains long-term persistence in networks"
        ],
        "typical_motivations": "Espionage, intellectual property theft, geopolitical advantage",
        "detection_difficulty": "High",
        "risk_color": "🔴"
    },
    1: {
        "name": "Organized Cybercrime",
        "description": "Profit-driven criminal organizations conducting mass-scale attacks",
        "characteristics": [
            "High-volume, automated attack campaigns",
            "Frequently uses URL shorteners and IP addresses",
            "Poor SSL certificate management",
            "Rapid domain cycling and infrastructure changes",
            "Mass-produced phishing kits and templates"
        ],
        "typical_motivations": "Financial gain, credential harvesting, ransomware deployment",
        "detection_difficulty": "Medium",
        "risk_color": "🟠"
    },
    2: {
        "name": "Hacktivist Group",
        "description": "Ideologically motivated actors conducting targeted campaigns",
        "characteristics": [
            "Opportunistic attack methods",
            "High use of political or social keywords",
            "Mixed sophistication levels",
            "Targets aligned with ideological beliefs",
            "Often announces attacks publicly"
        ],
        "typical_motivations": "Political activism, social justice, protest against organizations",
        "detection_difficulty": "Medium",
        "risk_color": "🟡"
    }
}

# --- Load Models ---
@st.cache_resource
def load_assets():
    classification_model_path = 'models/phishing_url_detector'
    clustering_model_path = 'models/threat_actor_profiler'
    plot_path = 'models/feature_importance.png'

    classification_model = None
    clustering_model = None
    plot = None

    if os.path.exists(classification_model_path + '.pkl'):
        classification_model = load_classification_model(classification_model_path)

    if os.path.exists(clustering_model_path + '.pkl'):
        clustering_model = load_clustering_model(clustering_model_path)

    if os.path.exists(plot_path):
        plot = plot_path

    return classification_model, clustering_model, plot

classification_model, clustering_model, feature_plot = load_assets()

if not classification_model:
    st.error(
        "Classification model not found. Please wait for the initial training to complete, or check the container logs with `make logs` if the error persists.")
    st.stop()

if not clustering_model:
    st.warning("Clustering model not found. Threat attribution will be unavailable.")

# --- Sidebar for Inputs ---
with st.sidebar:
    st.title("🔬 URL Feature Analysis")
    st.write("Describe the characteristics of a suspicious URL below.")

    # Get the actual URL input
    url_input = st.text_input("Enter URL to analyze", value="https://example.com")

    # Simplified form values to match the trained model's features
    form_values = {
        'url': url_input,
        'URL_Length': st.select_slider("URL Length", options=['Short', 'Normal', 'Long'], value='Long'),
        'having_Sub_Domain': st.select_slider("Sub-domain Complexity", options=['None', 'One', 'Many'], value='One'),
        'having_IP_Address': st.checkbox("URL uses an IP Address", value=False),
        'Shortining_Service': st.checkbox("Is it a shortened URL", value=False),
        'Prefix_Suffix': st.checkbox("URL has a Prefix/Suffix (e.g.,'-')", value=True),
        'SSLfinal_State': st.select_slider("SSL Certificate Status", options=['Trusted', 'Suspicious', 'None'], value='Suspicious'),
        'has_redirect': st.checkbox("URL has redirect", value=False)
    }

    st.divider()
    genai_provider = st.selectbox("Select GenAI Provider", ["Gemini", "OpenAI", "Grok"])
    submitted = st.button("🔍 Analyze & Attribute Threat", use_container_width=True, type="primary")

# --- Main Page ---
st.title("🛡️ Cognitive SOAR: Phishing Attribution System")
st.markdown("*From prediction to attribution - Advanced threat intelligence powered by AI*")

if not submitted:
    col1, col2 = st.columns(2)

    with col1:
        st.info(
            "**How it works:**\n1. 📊 **Classify** - Determine if URL is malicious\n2. 🎯 **Attribute** - Identify likely threat actor profile\n3. 📋 **Prescribe** - Generate response plan")

    with col2:
        st.info(
            "**Threat Actor Profiles:**\n🔴 **State-Sponsored APT** - Nation-state actors\n🟠 **Organized Cybercrime** - Profit-driven groups\n🟡 **Hacktivist** - Ideologically motivated")

    if feature_plot:
        st.subheader("📈 Model Feature Importance")
        st.image(feature_plot, caption="Feature importance from the trained classification model")

else:
    # --- Data Preparation ---
    # Convert UI inputs to the model's feature format
    url_length_map = {'Short': 0, 'Normal': 1, 'Long': 2}
    subdomain_map = {'None': 0, 'One': 1, 'Many': 2}
    ssl_state_map = {'None': 0, 'Suspicious': 1, 'Trusted': 2}

    # Create the input DataFrame with the EXACT column names the model expects
    input_data = pd.DataFrame([{
    'url_length': 2 if len(form_values['url']) > 75 else 1 if len(form_values['url']) > 30 else 0,
    'special_chars': 1 if any(c in form_values['url'] for c in ['-', '_', '@', '#', '$']) else 0,
    'ip_in_url': 1 if form_values['having_IP_Address'] else 0,
    'subdomains': 2 if form_values['url'].count('.') > 2 else 1 if form_values['url'].count('.') > 1 else 0,
    'dots_in_url': form_values['url'].count('.'),
    'path_length': len(form_values['url'].split('/')[-1]),
    'has_query_string': 1 if '?' in form_values['url'] else 0,
    'has_redirect': 1 if form_values['has_redirect'] else 0,
    'digit_count': sum(c.isdigit() for c in form_values['url']),
    'tld_is_short': 1 if len(form_values['url'].split('.')[-1]) <= 3 else 0,
    'hyphen_in_domain': 1 if '-' in form_values['url'].split('/')[2] else 0,
    'sensitive_keywords': 1 if any(word in form_values['url'].lower() for word in ['login', 'verify', 'account', 'secure']) else 0
}])

    # --- Enhanced Analysis Workflow ---
    with st.status("🔄 Executing Cognitive SOAR playbook...", expanded=True) as status:
        st.write("▶️ **Phase 1: Threat Classification** - Analyzing URL features...")
        time.sleep(1)

        # Adjust classification threshold
        classification_model._final_estimator.set_params(**{'class_weight': {0: 1, 1: 2}})  # Higher weight for malicious class
        
        # Classification prediction
        classification_prediction = predict_classification(classification_model, data=input_data)
        is_malicious = classification_prediction['prediction_label'].iloc[0] == 1
        confidence_score = classification_prediction['prediction_score'].iloc[0]

        verdict = "MALICIOUS" if is_malicious else "BENIGN"
        st.write(f"▶️ **Classification Result:** {verdict} (Confidence: {confidence_score:.2%})")
        time.sleep(1)

        # Threat Attribution (only if malicious and clustering model available)
        threat_actor_profile = None
        cluster_id = None

        if is_malicious and clustering_model:
            st.write("▶️ **Phase 2: Threat Attribution** - Identifying threat actor profile...")
            time.sleep(1)

            # Clustering prediction
            clustering_prediction = predict_clustering(clustering_model, data=input_data)
            cluster_id = clustering_prediction['Cluster'].iloc[0]
            threat_actor_profile = THREAT_ACTOR_PROFILES.get(cluster_id)

            if threat_actor_profile:
                st.write(f"▶️ **Attribution Result:** {threat_actor_profile['name']} (Cluster {cluster_id})")
            time.sleep(1)

        # GenAI Prescription (only if malicious)
        prescription = None
        if is_malicious:
            st.write(f"▶️ **Phase 3: Response Generation** - Engaging {genai_provider} for action plan...")
            try:
                enhanced_context = input_data.iloc[0].to_dict()
                if threat_actor_profile:
                    enhanced_context['threat_actor'] = threat_actor_profile['name']
                    enhanced_context['actor_description'] = threat_actor_profile['description']

                prescription = generate_prescription(genai_provider, enhanced_context)
                status.update(label="✅ Cognitive SOAR Analysis Complete!", state="complete", expanded=False)
            except Exception as e:
                st.error(f"Failed to generate prescription: {e}")
                prescription = None
                status.update(label="⚠️ Analysis complete with GenAI error", state="error")
        else:
            status.update(label="✅ Analysis Complete - No threat detected", state="complete", expanded=False)

    # --- Enhanced Tabbed Output ---
    if is_malicious and threat_actor_profile:
        tab1, tab2, tab3 = st.tabs(["🎯 **Attribution**", "📊 **Classification**", "📋 **Response Plan**"])
    else:
        tab1, tab2 = st.tabs(["📊 **Classification**", "📋 **Response Plan**"])

    # Threat Attribution Tab (only shown if malicious and attributed)
    if is_malicious and threat_actor_profile:
        with tab1:
            st.subheader(f"{threat_actor_profile['risk_color']} Threat Actor Attribution")

            st.error(f"**Attributed to: {threat_actor_profile['name']}**", icon=threat_actor_profile['risk_color'])
            st.write(f"*{threat_actor_profile['description']}*")

            col1, col2 = st.columns(2)

            with col1:
                st.write("**🎯 Typical Characteristics:**")
                for char in threat_actor_profile['characteristics']:
                    st.write(f"• {char}")

            with col2:
                st.write("**📊 Profile Details:**")
                st.write(f"**Motivations:** {threat_actor_profile['typical_motivations']}")
                st.write(f"**Detection Difficulty:** {threat_actor_profile['detection_difficulty']}")
                st.write(f"**Cluster ID:** {cluster_id}")

            st.info(
                "💡 **Analyst Note:** This attribution is based on pattern analysis of URL characteristics. Consider additional IOCs and context for final determination.")

    # Classification Tab
    classification_tab = tab2 if (is_malicious and threat_actor_profile) else tab1
    with classification_tab:
        st.subheader("🔍 Classification Results")
        if is_malicious:
            st.error("**Prediction: Malicious Phishing URL**", icon="🚨")
        else:
            st.success("**Prediction: Benign URL**", icon="✅")

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Confidence Score", f"{confidence_score:.2%}")
        with col2:
            threat_level = "HIGH" if is_malicious and confidence_score > 0.8 else ("MEDIUM" if is_malicious else "LOW")
            st.metric("Threat Level", threat_level)

        st.caption("Classification confidence represents the model's certainty in its prediction.")

    # Response Plan Tab
    response_tab = tab3 if (is_malicious and threat_actor_profile) else tab2
    with response_tab:
        st.subheader("📋 Automated Response Plan")

        if prescription:
            st.success("🤖 AI-generated response plan available", icon="🎯")

            col1, col2 = st.columns(2)

            with col1:
                st.write("#### 🎯 Executive Summary")
                st.info(prescription.get("summary", "Threat summary not available"))

                risk_level = prescription.get("risk_level", "Unknown")
                if risk_level.lower() == "critical":
                    st.error(f"**Risk Level:** {risk_level}", icon="🔴")
                elif risk_level.lower() == "high":
                    st.warning(f"**Risk Level:** {risk_level}", icon="🟠")
                else:
                    st.info(f"**Risk Level:** {risk_level}")

            with col2:
                st.write("#### 🔧 Quick Actions")
                actions = prescription.get("recommended_actions", [])
                if actions:
                    for i, action in enumerate(actions[:3], 1):
                        st.write(f"**{i}.** {action}")

            st.write("#### 📨 Communication Draft")
            comm_draft = prescription.get("communication_draft", "No communication draft available")
            st.text_area("Draft Message", comm_draft, height=120, key="comm_draft")

            with st.expander("🔍 View Full AI Response"):
                st.json(prescription)

        elif is_malicious:
            st.warning("⚠️ Could not generate automated response plan. Manual analysis required.")
            st.write("**Recommended Manual Actions:**")
            st.write("1. 🚫 Block the suspicious URL in security systems")
            st.write("2. 📧 Alert users who may have interacted with this URL")
            st.write("3. 🔍 Investigate source of the phishing attempt")
            st.write("4. 📊 Update threat intelligence feeds")

        else:
            st.info("✅ No response plan needed - URL classified as benign")
            st.write("**Monitoring Actions:**")
            st.write("• Continue normal security monitoring")
            st.write("• Log URL analysis for future reference")
            st.write("• Consider user security awareness if suspicious characteristics were present")

# --- Footer ---
st.markdown("---")
st.markdown("*Cognitive SOAR v2.0 - Enhanced with AI-powered threat attribution capabilities*")