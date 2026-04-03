from setuptools import setup, find_packages

setup(
    name="fastmcp",
    version="2.14.0",
    description="The fast, Pythonic way to build MCP servers and clients.",
    author="Jeremiah Lowin",
    packages=find_packages(include=["fastmcp*"]),
    install_requires=[
        "authlib",
        "cyclopts",
        "exceptiongroup",
        "httpx",
        "jsonref",
        "jsonschema-path",
        "mcp",
        "openapi-pydantic",
        "packaging",
        "platformdirs",
        "py-key-value-aio",
        "pydantic",
        "pydocket",
        "pyperclip",
        "python-dotenv",
        "rich",
        "uvicorn",
        "websockets"
    ],
)