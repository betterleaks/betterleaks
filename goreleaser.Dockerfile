FROM alpine:3.22
LABEL org.opencontainers.image.source="https://github.com/betterleaks/betterleaks"
# Betterleaks never runs Git. Git and Bash are for patch pipelines such as the
# pre-commit hook: git diff --cached ... | betterleaks stdin --git-diff
RUN apk add --no-cache bash git
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/betterleaks /usr/bin/betterleaks
ENTRYPOINT ["betterleaks"]
