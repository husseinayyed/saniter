from setuptools import setup, find_packages

setup(
    name="saniter",
    version="0.1.1",
    packages=find_packages(),
    package_data={
        'saniter': [
            'models/*.joblib',
            'models/*.pkl',
        ],
    },
    include_package_data=True,  # This is crucial!
    install_requires=[
        "scikit-learn>=1.0.0",
        "pandas>=1.3.0",
        "numpy>=1.21.0",
        "joblib>=1.1.0",
    ],
    python_requires=">=3.8",
)