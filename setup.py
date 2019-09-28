"""
pymonocypher
"""

# See:
# https://packaging.python.org/en/latest/distributing.html
# https://github.com/pypa/sampleproject


import setuptools
import os

MYPATH = os.path.abspath(os.path.dirname(__file__))

try:
    from Cython.Build import cythonize
    USE_CYTHON = os.path.isfile(os.path.join(MYPATH, 'c_monocypher.pyx'))
except ImportError:
    USE_CYTHON = False


ext = '.pyx' if USE_CYTHON else '.c'
extensions = [
    setuptools.Extension('monocypher',
        sources=['c_monocypher' + ext, 'monocypher.c'],
        include_dirs=['.'],
    ),
]

if USE_CYTHON:
    from Cython.Build import cythonize
    extensions = cythonize(extensions)


# Get the long description from the README file
with open(os.path.join(MYPATH, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


setuptools.setup(
    name='pymonocypher',
    version='0.1.3',
    description='Python ctypes bindings to the Monocypher library',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/jetperch/pymonocypher',
    author='Jetperch LLC',
    author_email='joulescope-dev@jetperch.com',

    # Classifiers help users find your project by categorizing it.
    #
    # For a list of valid classifiers, see https://pypi.org/classifiers/
    classifiers=[  # Optional
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication',
        'Natural Language :: English',
        'Topic :: Security :: Cryptography',

        # Supported Python versions
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: C',
    ],

    keywords='cryto cryptography monocypher chacha blake2b 25519',
    install_requires = [],
    extras_require={
        'dev': ['check-manifest', 'Cython', 'coverage'],
    },
    ext_modules=extensions,

    project_urls={
        'Bug Reports': 'https://github.com/jetperch/pymonocypher/issues',
        'Source': 'https://github.com/jetperch/pymonocypher/',
    },
)
