from setuptools import setup, find_packages
setup(
    name="saniter",
    version="0.0.9",
    packages=find_packages(),
    install_requires=[
        "scikit-learn>=1.0.0",
        "pandas>=1.3.0",
        "numpy>=1.21.0",
        "joblib>=1.1.0",
    ],
    python_requires=">=3.8",
)