from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="adapol",
    version="1.0.0",
    author="AdaPol Team",
    description="Adaptive Multi-Cloud Least-Privilege Policy Generator for Serverless Workflows",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "aws": ["boto3>=1.26.0", "botocore>=1.29.0"],
        "azure": ["azure-identity>=1.12.0", "azure-mgmt-resource>=22.0.0"],
        "gcp": ["google-cloud-logging>=3.4.0", "google-cloud-functions>=1.9.0"],
        "optimization": ["z3-solver>=4.12.0"],
        "dev": ["pytest>=7.2.0", "black>=22.0.0", "mypy>=1.0.0"],
    },
    entry_points={
        "console_scripts": [
            "adapol=adapol.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
