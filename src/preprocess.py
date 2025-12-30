import pandas as pd
import re

def clean(text):
    text = text.lower()
    text = re.sub(r'[^a-z ]','',text)
    return text

def load_data(path):
    df = pd.read_csv(path)
    df["text"] = df["title"].fillna("") + " " + df["description"].fillna("")
    df["text"] = df["text"].apply(clean)
    return df["text"], df["fraudulent"]
