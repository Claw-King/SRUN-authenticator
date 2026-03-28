FROM python:3.11-slim-bullseye AS build
COPY requirements.txt /requirements.txt
RUN apt-get update && \
    apt-get install --no-install-suggests --no-install-recommends --yes gcc python3-dev && \
    python3 -m venv /venv && \
    /venv/bin/pip install --upgrade pip setuptools wheel && \
    /venv/bin/pip install --disable-pip-version-check -r /requirements.txt

FROM python:3.11-slim-bullseye
LABEL maintainer="iskoldt-X"
COPY --from=build /venv /venv
COPY ./srun_login_pro.py /app/srun_login.py
WORKDIR /app

ENV PATH="/venv/bin:$PATH"
ENV SLEEP_TIME=300

# Set default values for UCAS (based on your prior config)
ENV GET_IP_API="http://124.16.81.61/cgi-bin/rad_user_info?callback=JQuery"
ENV GET_CHALLENGE_API="https://portal.ucas.ac.cn/cgi-bin/get_challenge"
ENV SRUN_PORTAL_API="https://portal.ucas.ac.cn/cgi-bin/srun_portal"

CMD ["python", "srun_login.py"]
