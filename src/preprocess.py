import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from clean import clean_text

def load_and_preprocess(csv_path):
    df = pd.read_csv("./dataset/fake_job_postings.csv")

    # Combine text columns
    df['text'] = (
        df['title'].astype(str) + " " +
        df['company_profile'].astype(str) + " " +
        df['description'].astype(str) + " " +
        df['requirements'].astype(str) + " " +
        df['benefits'].astype(str)
    )

    # Target
    df['fraudulent'] = df['fraudulent'].fillna(0).astype(int)

    # Clean text
    df['clean_text'] = df['text'].apply(clean_text)

    vectorizer = TfidfVectorizer(
        stop_words='english',
        max_features=3000
    )

    X = vectorizer.fit_transform(df['clean_text'])
    y = df['fraudulent']

    return X, y, vectorizer
