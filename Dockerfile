# syntax=docker/dockerfile:1

FROM eclipse-temurin:21-jdk-noble AS build
WORKDIR /build

COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
RUN chmod +x mvnw

COPY src/main/ src/main/

# Tests wajib dijalankan sebelum docker build melalui perintah langkah 5.
# Tahap ini hanya melakukan packaging.
RUN --mount=type=cache,target=/root/.m2 \
    ./mvnw -B -ntp -Dmaven.test.skip=true package \
    && cp target/auth-service-*.jar /build/app.jar

FROM eclipse-temurin:21-jre-noble AS runtime
WORKDIR /app

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app \
       --no-create-home --shell /usr/sbin/nologin app

COPY --from=build --chown=10001:10001 /build/app.jar /app/app.jar

USER 10001:10001
EXPOSE 8081

ENTRYPOINT ["java", "-XX:MaxRAMPercentage=70.0", "-XX:+ExitOnOutOfMemoryError", "-jar", "/app/app.jar"]