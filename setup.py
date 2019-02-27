"""
setup module for trustymail

Based on:

- https://github.com/cisagov/pshtt
"""

from setuptools import setup
from trustymail import __version__


def readme():
    with open('README.md') as f:
        return f.read()


with open('requirements.txt') as fp:
    reqs = [line.strip() for line in fp.readlines() if line]

with open('requirements-dev.txt') as fp:
    lines = [line.strip() for line in fp.readlines() if line]
    dev_reqs = [line for line in lines if line and '-r requirements.txt' not in line]


setup(
    name='trustymail',
    version=__version__,
    description='Scan domains and return data based on trustworthy email best practices',
    long_description=readme(),
    long_description_content_type='text/markdown',

    # NCATS "homepage"
    url="https://www.us-cert.gov/resources/ncats",
    # The project's main homepage
    download_url='https://github.com/cisagov/trustymail',

    # Author details
    author='Cyber and Infrastructure Security Agency',
    author_email='ncats@hq.dhs.gov',

    license='License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',

        # Pick your license as you wish (should match "license" above)
        'License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],

    # What does your project relate to?
    keywords='email authentication, STARTTLS',

    packages=['trustymail'],

    install_requires=reqs,

    extras_require={
        'dev': dev_reqs,
    },

    scripts=['scripts/trustymail']
)
