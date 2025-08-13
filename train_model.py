import pandas as pd
import numpy as np
import os
import streamlit as st
import time

# Import PyCaret Classification functions
from pycaret.classification import setup, compare_models, finalize_model, save_model, plot_model, create_model

# Import PyCaret Clustering functions
import pycaret.clustering


# Function to generate synthetic data with matching column names
def generate_synthetic_data(num_state_sponsored=120, num_organized_crime=200, num_hacktivist=120, num_benign=160):
    print("Generating synthetic dataset with threat actor profiles...")
    print(
        f"Generating {num_state_sponsored} State-Sponsored, {num_organized_crime} Organized Crime, {num_hacktivist} Hacktivist, and {num_benign} Benign samples...")

    data_list = []

    # State-Sponsored Samples (Cluster 0)
    for _ in range(num_state_sponsored):
        data_list.append({
            'having_IP_Address': -1,  # Rarely use IP addresses
            'URL_Length': 1,  # Long URLs
            'Shortining_Service': -1,  # Don't use URL shorteners
            'having_At_Symbol': -1,  # Default safe value
            'double_slash_redirecting': -1,  # Default safe value
            'Prefix_Suffix': 1,  # Use prefix/suffix manipulation
            'having_Sub_Domain': 1,  # Many subdomains
            'SSLfinal_State': 1,  # Valid SSL certificates
            'URL_of_Anchor': 0,  # Default value
            'Links_in_tags': 0,  # Default value
            'SFH': 0,  # Default value
            'Abnormal_URL': 1,  # Abnormal but sophisticated
            'has_political_keyword': -1,  # Usually no political keywords
            'domain_age_suspicious': -1,  # Domains appear legitimate
            'label': 1,
            'true_actor_profile': 'State-Sponsored'
        })

    # Organized Crime Samples (Cluster 1)
    for _ in range(num_organized_crime):
    # Use real-world phishing patterns in the synthetic data
       phishing_urls = [
        "https://appleid.apple.com.verify.account.security-update.com",
        "https://netflix.com-login.secure-confirm.com", 
        "https://microsoftonline.verify-credentials.com",
        "https://paypal.com-security-alert-verify-account.login.php"
    ]
    base_url = np.random.choice(phishing_urls)
    
    data_list.append({
        'having_IP_Address': np.random.choice([1, -1], p=[0.7, 0.3]),
        'URL_Length': 1,  # Force long URLs for phishing
        'Shortining_Service': np.random.choice([1, -1], p=[0.6, 0.4]),
        'having_At_Symbol': np.random.choice([1, -1], p=[0.2, 0.8]),
        'double_slash_redirecting': np.random.choice([1, -1], p=[0.3, 0.7]),
        'Prefix_Suffix': 1,  # Always use prefix/suffix for phishing
        'having_Sub_Domain': 1,  # Multiple subdomains
        'SSLfinal_State': np.random.choice([-1, 0], p=[0.7, 0.3]),  # Mostly suspicious/no SSL
        'URL_of_Anchor': np.random.choice([0, 1], p=[0.7, 0.3]),
        'Links_in_tags': np.random.choice([0, 1], p=[0.6, 0.4]),
        'SFH': np.random.choice([0, 1], p=[0.7, 0.3]),
        'Abnormal_URL': 1,  # Always abnormal
        'has_political_keyword': -1,
        'domain_age_suspicious': np.random.choice([1, -1], p=[0.8, 0.2]),  # Usually suspicious
        'label': 1,
        'true_actor_profile': 'Organized Crime'
    })

    # Hacktivist Samples (Cluster 2)
    for _ in range(num_hacktivist):
        data_list.append({
            'having_IP_Address': -1,  # Usually don't use IP addresses
            'URL_Length': np.random.choice([-1, 0, 1], p=[0.3, 0.4, 0.3]),  # Variable length
            'Shortining_Service': np.random.choice([1, -1], p=[0.3, 0.7]),  # Sometimes use shorteners
            'having_At_Symbol': -1,  # Default safe value
            'double_slash_redirecting': np.random.choice([1, -1], p=[0.2, 0.8]),  # Rare redirects
            'Prefix_Suffix': np.random.choice([1, -1], p=[0.6, 0.4]),  # Often use prefix/suffix
            'having_Sub_Domain': np.random.choice([-1, 0, 1], p=[0.4, 0.3, 0.3]),  # Variable subdomains
            'SSLfinal_State': np.random.choice([-1, 0, 1], p=[0.2, 0.3, 0.5]),  # Mixed SSL usage
            'URL_of_Anchor': 0,  # Default value
            'Links_in_tags': 0,  # Default value
            'SFH': 0,  # Default value
            'Abnormal_URL': np.random.choice([1, -1], p=[0.7, 0.3]),  # Usually abnormal
            'has_political_keyword': np.random.choice([1, -1], p=[0.8, 0.2]),  # Often political keywords
            'domain_age_suspicious': np.random.choice([1, -1], p=[0.4, 0.6]),  # Mixed domain ages
            'label': 1,
            'true_actor_profile': 'Hacktivist'
        })

    # Benign Samples
    for _ in range(num_benign):
        data_list.append({
            'having_IP_Address': -1,  # No IP addresses
            'URL_Length': np.random.choice([-1, 0], p=[0.7, 0.3]),  # Short to normal URLs
            'Shortining_Service': -1,  # No URL shorteners
            'having_At_Symbol': -1,  # No @ symbols
            'double_slash_redirecting': -1,  # No redirects
            'Prefix_Suffix': -1,  # No prefix/suffix
            'having_Sub_Domain': np.random.choice([-1, 0], p=[0.6, 0.4]),  # Few subdomains
            'SSLfinal_State': 1,  # Valid SSL certificates
            'URL_of_Anchor': -1,  # Safe anchors
            'Links_in_tags': -1,  # Safe links
            'SFH': -1,  # Safe forms
            'Abnormal_URL': -1,  # Normal URLs
            'has_political_keyword': -1,  # No political keywords
            'domain_age_suspicious': -1,  # Legitimate domains
            'label': 0,
            'true_actor_profile': 'Benign'
        })

    df = pd.DataFrame(data_list)
    return df


# Main training function
def train():
    classification_model_path = 'models/phishing_url_detector'
    clustering_model_path = 'models/threat_actor_profiler'
    plot_path = 'models/feature_importance.png'

    # Check if models already exist
    if os.path.exists(classification_model_path + '.pkl') and os.path.exists(clustering_model_path + '.pkl'):
        print("Models already exist. Skipping training.")
        return

    # Generate synthetic data
    data = generate_synthetic_data()
    os.makedirs('data', exist_ok=True)
    data.to_csv('data/phishing_synthetic_enhanced.csv', index=False)

    print(f"Generated data shape: {data.shape}")
    print(f"Generated columns: {list(data.columns)}")

    # ========== CLASSIFICATION MODEL TRAINING ==========
    print("\n=== PHASE 1: CLASSIFICATION MODEL TRAINING ===")
    print("Initializing PyCaret Classification Setup...")

    # Prepare data for classification (exclude actor profile columns)
    classification_data = data.drop(['true_actor_profile'], axis=1)
    print(f"Classification data shape: {classification_data.shape}")
    print(f"Classification columns: {list(classification_data.columns)}")

    try:
        clf_setup = setup(data=classification_data, target='label', session_id=42, train_size=0.8, verbose=False,fix_imbalance=True)
    except Exception as e:
        print(f"Failed to initialize PyCaret Classification setup. Error: {e}")
        return

    print("Comparing classification models...")
    try:
        best_clf_model = compare_models(include=['rf', 'et', 'lightgbm'], sort='Accuracy', n_select=1, verbose=False)
    except Exception as e:
        print(f"Compare models error: {e}, falling back to create_model")
        best_clf_model = create_model('rf', verbose=False)

    # Ensure we have a single model object
    if isinstance(best_clf_model, list):
        best_clf_model = best_clf_model[0]

    print("Finalizing classification model...")
    final_clf_model = finalize_model(best_clf_model)

    # Save feature importance plot
    print("Saving feature importance plot...")
    os.makedirs('models', exist_ok=True)
    try:
        plot_model(final_clf_model, plot='feature', save=True)
        os.rename('Feature Importance.png', plot_path)
    except Exception as e:
        print(f"Failed to save feature importance plot. Error: {e}")

    print("Saving classification model...")
    save_model(final_clf_model, classification_model_path)

    # ========== CLUSTERING MODEL TRAINING ==========
    print("\n=== PHASE 2: THREAT ATTRIBUTION CLUSTERING ===")

    # Prepare data for clustering: only malicious samples, features only (no labels)
    malicious_data = data[data['label'] == 1].copy()
    clustering_features = malicious_data.drop(['label', 'true_actor_profile'], axis=1)

    print(f"Training clustering model on {len(clustering_features)} malicious samples...")
    print(f"Clustering features: {list(clustering_features.columns)}")
    print("Initializing PyCaret Clustering Setup...")

    try:
        cluster_setup = pycaret.clustering.setup(data=clustering_features, session_id=42, verbose=False)
    except Exception as e:
        print(f"Failed to initialize PyCaret Clustering setup. Error: {e}")
        return

    print("Creating and tuning clustering models...")
    kmeans_model = pycaret.clustering.create_model('kmeans', num_clusters=3)

    print("Evaluating clustering model...")
    try:
        # Note: evaluate_model can cause issues in non-interactive environments,
        # but we'll leave it for now to see if it works.
        pycaret.clustering.evaluate_model(kmeans_model)
    except Exception as e:
        print(f"Model evaluation failed. Error: {e}")

    # Finalize model is not used for clustering, so we can save and predict directly.
    print("Saving clustering model...")
    pycaret.clustering.save_model(kmeans_model, clustering_model_path)

    # ========== CLUSTERING ANALYSIS ==========
    print("\n=== CLUSTERING ANALYSIS ===")

    # Predict clusters for analysis
    clustered_data = pycaret.clustering.predict_model(kmeans_model, data=clustering_features)

    # Analyze cluster characteristics
    analysis_data = malicious_data.copy()
    analysis_data['predicted_cluster'] = clustered_data['Cluster'].values

    print("\nCluster Analysis Summary:")
    for cluster_id in sorted(analysis_data['predicted_cluster'].unique()):
        cluster_samples = analysis_data[analysis_data['predicted_cluster'] == cluster_id]
        print(f"\n--- Cluster {cluster_id} ({len(cluster_samples)} samples) ---")
        print(f"True Actor Distribution:")
        actor_dist = cluster_samples['true_actor_profile'].value_counts()
        for actor, count in actor_dist.items():
            percentage = (count / len(cluster_samples)) * 100
            print(f"  {actor}: {count} ({percentage:.1f}%)")

        # Key characteristics
        print("Key Characteristics:")
        feature_means = cluster_samples.drop(['label', 'true_actor_profile', 'predicted_cluster'], axis=1).mean()
        top_features = feature_means.nlargest(3)
        for feature, value in top_features.items():
            print(f"  {feature}: {value:.2f}")

    print(f"\nBoth models trained and saved successfully!")
    print(f"Classification model: {classification_model_path}.pkl")
    print(f"Clustering model: {clustering_model_path}.pkl")
    print(f"Feature importance plot: {plot_path}")


if __name__ == "__main__":
    train()