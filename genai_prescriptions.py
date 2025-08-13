# genai_prescriptions.py
import google.generativeai as genai
import openai
import requests
import streamlit as st
import json
from datetime import datetime

try:
    genai.configure(api_key=st.secrets["GEMINI_API_KEY"])
    openai.api_key = st.secrets["OPENAI_API_KEY"]
    grok_api_key = st.secrets["GROK_API_KEY"]
except (KeyError, FileNotFoundError):
    print("API keys not found in .streamlit/secrets.toml. Some features may be disabled.")
    grok_api_key = None

def get_base_prompt(alert_details):
    """Enhanced prompt with threat actor attribution context"""
    
    # Extract threat actor information if available
    threat_actor = alert_details.get('threat_actor', 'Unknown')
    actor_description = alert_details.get('actor_description', '')
    
    # Build enhanced context
    context_parts = [
        "You are an expert Security Orchestration, Automation, and Response (SOAR) system.",
        "A URL has been flagged as a potential phishing attack with the following characteristics:"
    ]
    
    # Add technical features
    technical_features = {k: v for k, v in alert_details.items() 
                         if k not in ['threat_actor', 'actor_description']}
    context_parts.append(f"Technical Features: {json.dumps(technical_features, indent=2)}")
    
    # Add threat attribution if available
    if threat_actor != 'Unknown':
        context_parts.extend([
            f"\nTHREAT ATTRIBUTION ANALYSIS:",
            f"Attributed Threat Actor: {threat_actor}",
            f"Actor Profile: {actor_description}",
            f"\nThis attribution provides important context for response planning."
        ])
    
    context_parts.extend([
        "\nYour task is to generate a prescriptive incident response plan tailored to this specific threat.",
        "Consider the threat actor profile (if available) when recommending actions and communication strategies.",
        "\nProvide your response in a structured JSON format with the following keys:",
        '- "summary": A brief, one-sentence summary of the threat including actor attribution if available.',
        '- "risk_level": A single-word risk level (e.g., "Critical", "High", "Medium") considering the threat actor sophistication.',
        '- "recommended_actions": A list of 5-7 specific, technical, step-by-step actions for a security analyst, prioritized by threat actor capabilities.',
        '- "communication_draft": A professional draft to communicate to the employee who reported the suspicious URL, mentioning threat context appropriately.',
        '- "threat_context": Additional context about why this threat actor attribution matters for response planning.',
        "\nReturn ONLY the raw JSON object and nothing else."
    ])
    
    return '\n'.join(context_parts)

def get_gemini_prescription(alert_details):
    """Get prescription from Google Gemini with enhanced context"""
    model = genai.GenerativeModel('gemini-1.5-flash')
    prompt = get_base_prompt(alert_details)
    
    try:
        response = model.generate_content(prompt)
        response_text = response.text.strip()
        
        # Clean up response text (remove markdown formatting)
        response_text = response_text.lstrip("```json\n").rstrip("```").strip()
        
        return json.loads(response_text)
    except Exception as e:
        # Fallback response
        return {
            "summary": f"Malicious URL detected with potential {alert_details.get('threat_actor', 'unknown')} attribution",
            "risk_level": "High",
            "recommended_actions": [
                "Block the suspicious URL in security systems immediately",
                "Alert users who may have interacted with this URL",
                "Investigate the source and scope of the phishing campaign",
                "Update threat intelligence feeds with new IOCs",
                "Monitor for similar attack patterns from this threat actor"
            ],
            "communication_draft": "We have identified a suspicious URL that may be part of a phishing campaign. Please avoid clicking on any suspicious links and report any similar messages to the security team.",
            "threat_context": "Analysis suggests this may be associated with advanced threat actors requiring elevated response measures.",
            "error": f"Gemini API error: {str(e)}"
        }

def get_openai_prescription(alert_details):
    """Get prescription from OpenAI with enhanced context"""
    try:
        client = openai.OpenAI(api_key=st.secrets["OPENAI_API_KEY"])
        prompt = get_base_prompt(alert_details)
        
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            temperature=0.3  # Lower temperature for more consistent responses
        )
        
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        # Fallback response
        return {
            "summary": f"Malicious URL detected with potential {alert_details.get('threat_actor', 'unknown')} attribution",
            "risk_level": "High",
            "recommended_actions": [
                "Immediately block the malicious URL across all security systems",
                "Conduct user impact assessment for potential exposure",
                "Initiate threat hunting for related IOCs and attack patterns",
                "Update security awareness training based on attack techniques observed",
                "Coordinate with threat intelligence team for actor attribution validation"
            ],
            "communication_draft": "Our security team has identified a phishing URL that poses a significant threat. If you received communications containing this URL, please do not click any links and forward the message to security@company.com for analysis.",
            "threat_context": "The sophisticated nature of this attack suggests advanced threat actor involvement requiring comprehensive response measures.",
            "error": f"OpenAI API error: {str(e)}"
        }

def get_grok_prescription(alert_details):
    """Get prescription from Grok/X.AI with enhanced context"""
    if not grok_api_key:
        return {
            "error": "Grok API key not configured.",
            "summary": "Grok service unavailable",
            "risk_level": "Unknown",
            "recommended_actions": ["Configure Grok API key to enable this service"],
            "communication_draft": "Please contact your security team for assistance.",
            "threat_context": "Grok analysis unavailable due to configuration issue."
        }
    
    try:
        prompt = get_base_prompt(alert_details)
        url = "https://api.x.ai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {grok_api_key}", 
            "Content-Type": "application/json"
        }
        data = {
            "model": "grok-1", 
            "messages": [{"role": "user", "content": prompt}], 
            "temperature": 0.4
        }
        
        response = requests.post(url, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        
        content_str = response.json()['choices'][0]['message']['content']
        content_str = content_str.strip().lstrip("```json\n").rstrip("```").strip()
        
        return json.loads(content_str)
    except Exception as e:
        # Fallback response
        return {
            "summary": f"Malicious URL requiring immediate attention - {alert_details.get('threat_actor', 'Unknown actor')} suspected",
            "risk_level": "High",
            "recommended_actions": [
                "Execute immediate URL blocking across all network security devices",
                "Launch comprehensive user communication campaign about this threat",
                "Initialize threat actor tracking and attribution validation procedures",
                "Activate incident response team for coordinated threat response",
                "Deploy additional monitoring for similar attack patterns"
            ],
            "communication_draft": "SECURITY ALERT: We have detected a sophisticated phishing campaign targeting our organization. Please exercise extreme caution with email links and report any suspicious messages immediately to our security team.",
            "threat_context": "This incident requires elevated response due to the potential involvement of advanced persistent threat actors.",
            "error": f"Grok API error: {str(e)}"
        }

def generate_prescription(provider, alert_details):
    """Generate prescription with enhanced threat actor context"""
    
    # Add timestamp and provider info to alert details
    enhanced_details = alert_details.copy()
    enhanced_details['analysis_provider'] = provider
    enhanced_details['analysis_timestamp'] = datetime.now().isoformat()
    
    if provider == "Gemini":
        return get_gemini_prescription(enhanced_details)
    elif provider == "OpenAI":
        return get_openai_prescription(enhanced_details)
    elif provider == "Grok":
        return get_grok_prescription(enhanced_details)
    else:
        raise ValueError(f"Invalid provider selected: {provider}")

# Helper function to validate prescription format
def validate_prescription(prescription):
    """Validate that prescription contains required fields"""
    required_fields = ['summary', 'risk_level', 'recommended_actions', 'communication_draft']
    
    for field in required_fields:
        if field not in prescription:
            prescription[field] = f"Field '{field}' not available"
    
    if not isinstance(prescription.get('recommended_actions'), list):
        prescription['recommended_actions'] = ["Manual analysis required"]
    
    return prescription