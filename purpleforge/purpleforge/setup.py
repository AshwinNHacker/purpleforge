from setuptools import setup, find_packages

setup(
    name="purpleforge",
    version="0.1.0",
    description="MITRE ATT&CK detection validation framework — synthetic telemetry + rule engine + coverage reporting.",
    author="Shin",
    packages=find_packages(exclude=["tests"]),
    include_package_data=True,
    package_data={"purpleforge": ["detector/rules/*.yml"]},
    install_requires=["PyYAML>=6.0"],
    entry_points={
        "console_scripts": [
            "purpleforge=purpleforge.cli:main",
        ],
    },
    python_requires=">=3.9",
)
