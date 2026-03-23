# src/train_model.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
import os
import sys

# Add root folder to path to import feature_extraction
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from src.feature_extraction import extract_features

def train():
    print("=========================================")
    print("🚀 Loading Kaggle Balanced Dataset...")
    print("=========================================")
    
    csv_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'dataset.csv')
    
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"❌ Error loading CSV: {e}")
        sys.exit(1)

    # Make column names lowercase to avoid case-sensitivity errors
    df.columns = df.columns.str.lower()

    if 'url' not in df.columns or 'label' not in df.columns:
        print("❌ Error: Column names do not match!")
        print(f"Found columns: {df.columns.tolist()}")
        print("Please open dataset.csv and rename columns to 'url' and 'label'")
        sys.exit(1)

    # Drop any empty rows (Clean the data)
    df = df.dropna(subset=['url', 'label'])

    print("Processing labels (Converting text to numbers)...")
    # Convert 'bad'/'phishing' to 1 and 'good'/'safe' to 0 automatically
    y_raw = df['label'].astype(str).str.lower().str.strip()
    y = y_raw.apply(lambda x: 1 if x in ['bad', 'phishing', '1', 'malicious'] else 0)

    print("Extracting features from URLs (this might take a minute)...")
    # If the dataset is too huge (like 500,000 rows), take a 50k sample so your laptop doesn't freeze
    if len(df) > 50000:
        print("Dataset is large! Using 50,000 random rows for faster training...")
        df_sampled = df.sample(n=50000, random_state=42)
        X = [extract_features(url) for url in df_sampled['url']]
        y = y.loc[df_sampled.index]
    else:
        X = [extract_features(url) for url in df['url']]

    print("Training the AI model...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Check how smart our model became
    accuracy = accuracy_score(y_test, model.predict(X_test))
    print(f"🎯 Model Accuracy: {accuracy * 100:.2f}%")

    print("Saving model to 'model' folder...")
    model_path = os.path.join(os.path.dirname(__file__), '..', 'model', 'phishing_model.pkl')
    joblib.dump(model, model_path)
    
    print("✅ Training Complete! You can now run app.py")

if __name__ == "__main__":
    train()