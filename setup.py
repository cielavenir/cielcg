from setuptools import setup

setup(
    name='cielcg',
    description='alternative cgroup-tools (cgexec) implementation for both cgroup v1 and v2 (cgroup2)',
    long_description=open("README.md").read(),
    version='0.0.0.1',
    url='https://github.com/cielavenir/cielcg',
    license='BSD',
    author='cielavenir',
    author_email='cielartisan@gmail.com',
    py_modules=['cielcg'],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX :: Linux',
        'Topic :: System :: Operating System',
        'Topic :: Software Development :: Libraries',
        'Topic :: Utilities',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: PyPy',
    ]
)
