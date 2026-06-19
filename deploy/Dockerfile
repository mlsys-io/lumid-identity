FROM --platform=linux/amd64 golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 go build -o /out/identity ./cmd/identity

FROM --platform=linux/amd64 alpine:3.20
# git is invoked by /admin/loops → loadAppGitStatus to inspect the
# bind-mounted ~/.xp/apps/<name>/.git directories (dirty / ahead /
# behind / HEAD sha). Without it those fields are silently empty.
# util-linux-misc (prlimit + setpriv) + python3: the code_run agent
# tool wraps `python3 -c "<code>"` in:
#   prlimit --as=512M --cpu=30 --nproc=64 --fsize=10M \
#   setpriv --reuid 65534 --regid 65534 --clear-groups \
#           --no-new-privs --inh-caps -all --bounding-set -all \
#   python3 -c <code>
#
# This is the lightest viable sandbox inside a non-privileged docker
# container (no CAP_SYS_ADMIN available → bwrap/userns is unavailable
# without significant cap grants). Trade-off: no network namespace —
# the sandboxed process can reach the same hosts identity itself can.
# Identity is single-tenant + operator-trusted, so the residual risk
# is bounded by identity's own egress reachability.
# Document extraction toolchain for chat file uploads:
#   - poppler-utils → pdftotext (PDF fallback when provider lacks
#                     native document blocks; Claude path bypasses
#                     this and ships the PDF as an Anthropic
#                     `document` content block).
#   - pandoc        → docx, rtf, odt, epub, html → plain text. Single
#                     binary, no per-format extractor needed.
#   - py3-openpyxl  → xlsx extractor (pandoc doesn't read xlsx;
#                     openpyxl + a 30-line stdlib helper covers cells
#                     + sheet names).
RUN apk add --no-cache \
      ca-certificates tzdata git util-linux-misc python3 \
      poppler-utils pandoc py3-openpyxl py3-yaml
WORKDIR /app
COPY --from=builder /out/identity /app/identity
COPY configs/identity.yaml /app/configs/identity.yaml
ENV TZ=Asia/Singapore
EXPOSE 9900
ENTRYPOINT ["/app/identity", "-c", "/app/configs/identity.yaml"]
