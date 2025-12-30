from src.preprocess import load_data
from src.train import train

X,y = load_data("dataset/fake_job_postings.csv")
model, vectorizer = train(X,y)

def predict_text(text):
    vec = vectorizer.transform([text])
    return "FAKE JOB ❌" if model.predict(vec)[0]==1 else "LEGIT JOB ✅"

def predict_image(path):
    return "FAKE JOB ❌ (Image Based)"
