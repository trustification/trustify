# Builder image
FROM registry.access.redhat.com/ubi9/nodejs-20:latest as builder

USER 1001
COPY --chown=1001 . .
RUN npm clean-install --ignore-scripts && npm run build && npm run dist

# Runner image
FROM registry.access.redhat.com/ubi9/nodejs-20-minimal:latest

# Add ps package to allow liveness probe for k8s cluster
# Add tar package to allow copying files with kubectl scp
USER 0
RUN microdnf -y install tar procps-ng && microdnf clean all

USER 1001

LABEL name="trustify/trustify-ui" \
      description="Trustify - User Interface" \
      help="For more information visit https://trustification.github.io/" \
      license="Apache License 2.0" \
      maintainer="carlosthe19916@gmail.com" \
      summary="Trustify - User Interface" \
      url="https://ghcr.io/trustification/trustify-ui" \
      usage="podman run -p 80 -v trustification/trustify-ui:latest" \
      io.k8s.display-name="trustify-ui" \
      io.k8s.description="Trustify - User Interface" \
      io.openshift.expose-services="80:http" \
      io.openshift.tags="operator,trustification,trustify,ui,nodejs20" \
      io.openshift.min-cpu="100m" \
      io.openshift.min-memory="350Mi"

COPY --from=builder /opt/app-root/src/dist /opt/app-root/dist/

ENV DEBUG=1

WORKDIR /opt/app-root/dist
ENTRYPOINT ["./entrypoint.sh"]
