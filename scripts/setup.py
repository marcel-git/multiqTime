from distutils.core import setup, Extension

def main():
  setup(
    name="Transmission Module",
    version="1.0.0",
    description="Module for transmitting a series of TCP segments in python",
    author="Marcel Kühn",
    author_email="marcel.kuehn@tu-dortmund.de",
    ext_modules=[Extension("modTransmit", ["send.c"])] # Name of the module to convert to an extension
  )

if (__name__ == "__main__"):
    main()