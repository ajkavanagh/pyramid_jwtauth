
import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.rst')) as f:
    README = f.read()

with open(os.path.join(here, 'CHANGES.txt')) as f:
    CHANGES = f.read()

# TODO: fix the imports.
requires = ['pyramid >= 1.3', 'webtest', 'pycrypto']

setup(name='pyramid_jwtauth',
      version='0.0.1.dev3',
      description='pyramid_jwtauth',
      long_description=README + '\n\n' + CHANGES,
      license='MPLv2.0',
      classifiers=[
        "Programming Language :: Python",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        ],
      author='Alex Kavanagh (Websand)',
      author_email='alex@ajkavanagh.co.uk',
      url='https://github.com/ajkavanagh/pyramid_jwtauth',
      keywords='authentication token JWT JSON',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=requires,
      test_suite="pyramid_jwtauth")
