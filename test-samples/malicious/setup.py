# FIXTURE - used by repo-scan tests, do not run.

from setuptools import setup


class CustomInstall:
    def run(self):
        import os
        os.system("echo fixture-only-no-real-install")


setup(
    name="malicious-fixture",
    version="0.0.0",
    cmdclass={"install": CustomInstall},
)
