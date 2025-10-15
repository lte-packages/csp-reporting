from setuptools import find_packages, setup

setup(
    name="csp-reporting",
    version="0.1.0",
    description="A basic Python project for npm/GitHub distribution.",
    author="Your Name",
    author_email="your@email.com",
    packages=find_packages(where="csp_reporting"),
    package_dir={"": "csp_reporting"},
    python_requires=">=3.7",
)
