from preprocess import load_and_preprocess
from train import trained_model
from clean import clean_text

# Load and preprocess data
X, y, vectorizer = load_and_preprocess("./dataset/fake_job_postings.csv")

print("Real jobs:", (y == 0).sum())
print("Fake jobs:", (y == 1).sum())

# Train model
model = trained_model(X, y)

# Test prediction
sample_text = """
Description:
We are looking for a Data Analyst to analyze business data and prepare reports.
The candidate should work with Excel, SQL, and Python to find useful insights.
You will support the management team by creating dashboards and charts.

Requirements:

Bachelor’s degree in Computer Science or related field

Basic knowledge of Python and SQL

Good communication skills

Salary: ₹5–7 LPA
Official Email: hr@abctech.com
"""

cleaned = clean_text(sample_text)
vector = vectorizer.transform([cleaned])
prediction = model.predict(vector)[0]

print("\nPrediction Result:")
print("FAKE JOB" if prediction == 1 else "REAL JOB")
