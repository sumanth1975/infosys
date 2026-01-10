from sklearn.model_selection import train_test_split
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import accuracy_score, classification_report
from imblearn.over_sampling import SMOTE
import joblib
import os

def trained_model(X, y, vectorizer):
    # 1️⃣ Train-test split FIRST
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 2️⃣ Apply SMOTE ONLY on training data
    smote = SMOTE(random_state=42)
    X_train_res, y_train_res = smote.fit_resample(X_train, y_train)

    # 3️⃣ Train model
    model = SGDClassifier(
        loss="log_loss",
        max_iter=2000,
        random_state=42
    )

    model.fit(X_train_res, y_train_res)

    # 4️⃣ Evaluate on ORIGINAL test set
    y_pred = model.predict(X_test)

    print("Accuracy:", accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred))

    # 5️⃣ Save model + vectorizer
    os.makedirs("model", exist_ok=True)
    joblib.dump(model, "model/job_model.pkl")
    joblib.dump(vectorizer, "model/tfidf_vectorizer.pkl")

    print("✅ Trained model and vectorizer saved")

    return model
