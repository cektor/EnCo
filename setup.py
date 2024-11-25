from setuptools import setup, find_packages

setup(
    name="enco",
    version="1.0",
    packages=find_packages(),
    install_requires=[
        # gerekli bağımlılıkları buraya ekleyin
    ],
    package_data={
        'enco': ['*.png', '*.desktop'],
    },
    data_files=[
        ('share/applications', ['enco.desktop']),
        ('~/.local/share', ['encolo.png']),
    ],
)