# syntax=docker/dockerfile:1.7

ARG NODE_IMAGE
FROM ${NODE_IMAGE}

ARG NODE_IMAGE
WORKDIR /app

COPY --chown=65532:65532 package.json ./package.json
COPY --chown=65532:65532 src ./src
COPY --chown=65532:65532 vendor ./vendor
COPY --chown=65532:65532 scripts/require-image-digest.mjs ./scripts/require-image-digest.mjs
COPY --from=release-config --chown=65532:65532 /deployment.json /app/config/deployment.json
COPY --from=release-config --chown=65532:65532 /key-bundle.ciphertext /app/config/key-bundle.ciphertext
COPY --from=release-config --chown=65532:65532 /transparency-key.ciphertext /app/config/transparency-key.ciphertext

RUN node ./scripts/require-image-digest.mjs "${NODE_IMAGE}" \
  && test -s /app/config/deployment.json \
  && test -s /app/config/key-bundle.ciphertext \
  && test -s /app/config/transparency-key.ciphertext

ENV NODE_ENV=production \
    HERD_DEPLOYMENT_CONFIG_FILE=/app/config/deployment.json

LABEL "tee.launch_policy.allow_capabilities"="false" \
      "tee.launch_policy.allow_cgroups"="false" \
      "tee.launch_policy.allow_cmd_override"="false" \
      "tee.launch_policy.allow_env_override"="" \
      "tee.launch_policy.allow_mount_destinations"="" \
      "tee.launch_policy.log_redirect"="never" \
      "tee.launch_policy.monitoring_memory_allow"="never"

USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8080/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]
CMD ["node", "src/server.mjs"]
