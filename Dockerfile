# Usage
#
# Virtual CCF (non-SGX) build and run:
#   $ docker build -t ghcr.io/scitt-community/scitt-api-emulator:main --progress plain .
#   $ docker run --rm -ti -w /src/src/scitt-api-emulator -v $PWD:/src/src/scitt-api-emulator -p 8000:8000 ghcr.io/scitt-community/scitt-api-emulator:main
FROM python:3.8

WORKDIR /usr/src/scitt-api-emulater

COPY setup.py ./
RUN mkdir -p scitt_emulater \
  && pip install --no-cache-dir -e .

COPY . .

RUN pip install --no-cache-dir -e .

CMD scitt-emulator server --workspace workspace/ --tree-alg CCF
