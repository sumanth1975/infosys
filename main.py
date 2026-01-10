from preprocess import load_and_preprocess
from train import trained_model
from clean import clean_text

X, y, vectorizer = load_and_preprocess("./dataset/fake_job_postings.csv")
model = trained_model(X, y, vectorizer)

sample_text = """
We are hiring a Data Analyst with experience in Python, SQL and Excel.
Salary 5–7 LPA. Official email: hr@abctech.com
"""

cleaned = clean_text(sample_text)
vector = vectorizer.transform([cleaned])
prediction = model.predict(vector)[0]

print("REAL JOB" if prediction == 0 else "FAKE JOB")
