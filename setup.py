from trustymail import __version__

"""
Setup module for trustymail

Based on:

- https://github.com/dhs-ncats/pshtt
"""

from setuptools import setup

setup(

        name='trustymail',
        version=__version__,
        description="Scan DNS records for best mail practices.",

        download_url="https://github.com/dhs-ncats/trustymail",

        packages=['trustymail'],

        install_requires=[
            'requests',
            'docopt',
            'py3dns',
            'pyspf==2.0.11',
            'publicsuffix'
        ],

        entry_points={
            'console_scripts': [
                'trustymail = trustymail.cli:main'
            ]
        }
)
