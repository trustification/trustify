######################################################################
# UI
######################################################################
FROM registry.access.redhat.com/ubi9/nodejs-20:latest AS ui-source
ARG ui_branch="main"
ARG ui_commit

USER root
RUN dnf install git -y

RUN git clone https://github.com/trustification/trustify-ui.git --branch ${ui_branch} /trustify-ui/
RUN cd /trustify-ui/ && if [ -n "${ui_commit}" ]; then git checkout -b commit-branch ${ui_commit}; fi
RUN chown -R 1001 /trustify-ui/

USER 1001
RUN npm install -g npm@9
RUN cd /trustify-ui/ && npm clean-install --ignore-scripts && npm run build && npm run dist

######################################################################
# Prepare server
######################################################################
FROM registry.access.redhat.com/ubi9/ubi:latest AS server-source
COPY . /trustify/
RUN sed -i 's/trustify-ui = { git = "https:\/\/github.com\/trustification\/trustify-ui.git", tag = "static-main" }/trustify-ui = { path = "..\/trustify-ui\/crate" }/g' /trustify/Cargo.toml

######################################################################
# Build server
######################################################################
FROM registry.access.redhat.com/ubi9/ubi:latest AS server-builder

# Dependencies
RUN dnf install -y openssl-devel gcc

RUN mkdir /stage/ && \
    dnf install --installroot /stage/ --setop install_weak_deps=false --nodocs -y zlib openssl && \
    dnf clean all --installroot /stage/

# Setup Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH=${PATH}:/root/.cargo/bin
RUN rustup target add $(uname -m)-unknown-linux-gnu

# Build source code
COPY --from=ui-source /trustify-ui/ /code/trustify-ui/
COPY --from=server-source /trustify/ /code/trustify/
RUN cd /code/trustify/ && \
    cargo build --no-default-features --release --target=$(uname -m)-unknown-linux-gnu && \
    find /code/trustify/target/ -name "trustd" -exec cp -av {} /stage/usr/local/bin \;

######################################################################
# Builder runner
######################################################################
FROM registry.access.redhat.com/ubi9/ubi-micro:latest AS server-runner
COPY --from=server-builder /stage/ .
ENTRYPOINT ["/usr/local/bin/trustd"]
