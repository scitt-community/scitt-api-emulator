FROM python:3.8

WORKDIR /usr/src/scitt-api-emulater

COPY setup.py ./
RUN mkdir -p scitt_emulater \
  && pip install --no-cache-dir -e .

COPY . .

RUN pip install --no-cache-dir -e .

CMD scitt-emulator server --workspace workspace/ --tree-alg CCF
