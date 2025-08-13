# predict/train.py
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
def train(X, y):
    base = LogisticRegression(max_iter=250, n_jobs=-1, class_weight="balanced")
    clf = CalibratedClassifierCV(base, method="isotonic", cv=5)
    clf.fit(X, y)
    return clf
