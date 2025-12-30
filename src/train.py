from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

def train(X,y):
    vectorizer = TfidfVectorizer(stop_words="english")
    Xv = vectorizer.fit_transform(X)
    model = LogisticRegression()
    model.fit(Xv,y)
    return model, vectorizer
